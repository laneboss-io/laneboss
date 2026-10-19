package identityd

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/identityd/ticket"
	"laneboss.io/laneboss/internal/instancename"
)

type issuerPeerKey struct{}
type issueRequest struct {
	Level int    `json:"level"`
	Role  string `json:"role"`
	TTL   string `json:"ttl"`
}

type humanAuthorizer struct{ server *Server }

func (a humanAuthorizer) RequireHuman(ctx context.Context) error {
	s := a.server
	peer, ok := ctx.Value(issuerPeerKey{}).(Peer)
	denied := &ticket.Refusal{Reason: ticket.HumanRequired}
	if !ok || peer.UID != s.options.HumanUID || peer.UID == s.process.UID {
		return denied
	}
	line, err := ancestry(peer)
	if err != nil || ctx.Err() != nil {
		return denied
	}
	s.mu.Lock()
	principal, err := s.store.resolve(line)
	s.mu.Unlock()
	_, tty, _, terminalError := processTerminal(peer.PID)
	if err != nil || terminalError != nil || !tty || principal.ID != "" {
		return denied
	}
	// This mutation restores the old unidentified + PTY rule at the real
	// authorization boundary. T8 must catch the detached orphan it admits.
	if faults.Get("ticket-human-pty").Point != "" {
		if faults.Reach("ticket-human-pty") != nil {
			return denied
		}
		return nil
	}
	if s.options.HumanSession == nil {
		return denied
	}
	login, err := processFor(*s.options.HumanSession)
	if err != nil || login.UID != peer.UID || login.Parent <= 1 || !inAncestry(login.Peer, line) {
		return denied
	}
	sid, loginTTY, _, err := processTerminal(login.PID)
	if err != nil || sid != login.PID || !loginTTY {
		return denied
	}
	return nil
}

func protectedPolicy(c *config.Configuration, uid uint32) error {
	if err := protectedAncestors(c.ConfigDir, uid); err != nil {
		return err
	}
	return filepath.WalkDir(c.ConfigDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		owner, _, _, err := ownership(info)
		if err != nil || owner != 0 && owner != uid || !info.IsDir() && !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
			return refuse("the service role policy is caller-writable\nInstead: provision the trusted configuration under the administrator or service account.")
		}
		return nil
	})
}

// trustedRole checks every source caller.Role can read, including the instance
// file below an org root. A protected root alone does not protect writable
// descendants. Apply this at issue and redemption, not only daemon startup.
func (s *Server) readTrustedRole(ctx context.Context, policy *config.Configuration, role string) (caller.Principal, error) {
	denied := &ticket.Refusal{Reason: ticket.InvalidScope}
	if policy == nil || ctx.Err() != nil || !instancename.Valid(role) {
		return caller.Principal{}, denied
	}
	supervisors, _ := policy.Data["supervisors"].(map[string]any)
	if _, configured := supervisors[role]; !configured {
		org := caller.OrgRoot(policy)
		if org == "" {
			return caller.Principal{}, errRoleRemoved
		}
		directory := filepath.Join(org, ".laneboss", "instances", role)
		info, err := os.Lstat(filepath.Join(directory, "instance.toml"))
		if os.IsNotExist(err) {
			return caller.Principal{}, errRoleRemoved
		}
		if err != nil {
			return caller.Principal{}, denied
		}
		if err := protectedAncestors(directory, s.process.UID); err != nil {
			return caller.Principal{}, denied
		}
		if !info.Mode().IsRegular() || info.Size() > 1<<20 || info.Mode().Perm()&0022 != 0 {
			return caller.Principal{}, denied
		}
		owner, _, _, err := ownership(info)
		if err != nil || owner != 0 && owner != s.process.UID {
			return caller.Principal{}, denied
		}
	}
	target, _, err := caller.Role(policy, role)
	if err != nil || ctx.Err() != nil {
		return caller.Principal{}, denied
	}
	return target, nil
}

func (s *Server) openTickets() error {
	if s.options.ConfigHome == "" {
		return nil
	}
	if s.options.HumanUID == 0 || s.options.HumanUID == s.process.UID || s.options.HumanSession == nil {
		return refuse("ticket issuance needs a separate human UID and an attested login session\nInstead: provision --human-uid and --human-session in the protected service definition.")
	}
	state, _ := s.options.roots()
	c, err := config.Load(s.options.Config, config.Options{Home: s.options.ConfigHome, StateHome: state})
	if err != nil {
		return refuse("the service's trusted configuration cannot be loaded\nInstead: provision --config-home for this configuration.")
	}
	if err := protectedPolicy(c, s.process.UID); err != nil {
		return err
	}
	s.policy = c
	file, err := privateFile(s.store.root, "tickets.sqlite", 0600)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", filepath.Join(s.store.root.Name(), "tickets.sqlite")+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)")
	if err != nil {
		return err
	}
	s.ticketDB = db
	s.tickets, err = ticket.NewStore(context.Background(), db, humanAuthorizer{s})
	if err != nil {
		return err
	}
	if s.options.Verifier == nil {
		s.options.Verifier = &ticket.RegistrationVerifier[Peer, Grant]{Tickets: s.tickets, ResolveGrant: s.resolveGrant}
	}
	return s.importLegacy()
}

func (s *Server) resolveGrant(ctx context.Context, issued ticket.Scope, peer Peer) (Grant, error) {
	if s.policy == nil || issued.Config != s.policy.Name || !issued.Valid() || ctx.Err() != nil {
		return Grant{}, &ticket.Refusal{Reason: ticket.InvalidScope}
	}
	target, err := s.trustedRole(ctx, issued.Role)
	if err != nil {
		if errors.Is(err, errRoleRemoved) {
			return Grant{}, policyRefusal(issued, nil, "removed")
		}
		if errors.Is(err, errPolicyUnavailable) {
			return Grant{}, policyRefusal(issued, nil, "unavailable")
		}
		return Grant{}, &ticket.Refusal{Reason: ticket.InvalidScope}
	}
	if target.Level < issued.Level {
		current := ticket.Scope{Config: issued.Config, Level: target.Level, Role: issued.Role}
		return Grant{}, policyRefusal(issued, &current, "")
	}
	line, err := ancestry(peer)
	if err != nil || len(line) < 2 || line[0].Parent != line[1].PID {
		return Grant{}, &ticket.Refusal{Reason: ticket.InvalidSession}
	}
	parent := line[1]
	sid, _, program, err := processTerminal(parent.PID)
	shared := map[string]bool{"sh": true, "bash": true, "zsh": true, "fish": true, "tmux": true, "screen": true, "systemd": true, "launchd": true, "sshd": true}
	if err != nil || sid != parent.PID || shared[program] || s.options.HumanSession != nil && parent.PID == s.options.HumanSession.PID {
		return Grant{}, &ticket.Refusal{Reason: ticket.InvalidSession}
	}
	// Role lookup may refuse a removed role and determines its namespace, but
	// its current level must never overwrite the level granted at issue.
	return Grant{Principal: Principal{ID: target.ID, Level: issued.Level}, Session: ProcessRef{PID: parent.PID, Start: parent.Start}, DedicatedSession: true}, nil
}

func (s *Server) issue(ctx context.Context, peer Peer, payload json.RawMessage) (string, error) {
	if s.tickets == nil || s.policy == nil {
		return "", &ticket.Refusal{Reason: ticket.Unavailable}
	}
	ctx = context.WithValue(ctx, issuerPeerKey{}, peer)
	if err := (humanAuthorizer{s}).RequireHuman(ctx); err != nil {
		return "", err
	}
	parsed, err := jsonObject(payload)
	if err != nil || len(parsed) != 3 {
		return "", &ticket.Refusal{Reason: ticket.InvalidScope}
	}
	role, roleOK := parsed["role"].(string)
	levelValue, levelOK := parsed["level"].(json.Number)
	level, levelErr := levelValue.Int64()
	lifetime, ttlOK := parsed["ttl"].(string)
	if !roleOK || !levelOK || levelErr != nil || !ttlOK || level < 3 || level > 6 {
		return "", &ticket.Refusal{Reason: ticket.InvalidScope}
	}
	target, err := s.trustedRole(ctx, role)
	if err != nil || target.Level != int(level) {
		return "", &ticket.Refusal{Reason: ticket.InvalidScope}
	}
	ttl, err := time.ParseDuration(lifetime)
	if err != nil {
		return "", &ticket.Refusal{Reason: ticket.InvalidTTL}
	}
	return s.tickets.Issue(ctx, ticket.Scope{Config: s.options.Config, Level: int(level), Role: role}, ttl)
}

// A small helper uses the same duplicate-key and Unicode validation as requests.
func jsonObject(data []byte) (map[string]any, error) {
	parsed, err := eventstore.Parse(data, "the issuance request")
	if err != nil {
		return nil, err
	}
	value, ok := parsed.(map[string]any)
	if !ok {
		return nil, &ticket.Refusal{Reason: ticket.InvalidScope}
	}
	return value, nil
}

func ticketFailure(err error) error {
	var r *ticket.Refusal
	if errors.As(err, &r) {
		return refuse(r.Error())
	}
	return err
}

func sharedProgram(path string) string {
	return strings.TrimSuffix(filepath.Base(path), " (deleted)")
}
