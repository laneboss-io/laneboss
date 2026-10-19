package identityd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/eventstore"
)

// LegacySnapshot is prepared and frozen by the administrator at activation.
// It records full current kernel identities, including Linux boot identity,
// rather than reopening mutable 0.7.0 session files on every caller lookup.
type LegacySnapshot struct {
	Config   string          `json:"config"`
	Sessions []LegacySession `json:"sessions"`
}

type LegacySession struct {
	Role    string `json:"role"`
	Process Peer   `json:"process"`
}

func (s *Server) importLegacy() error {
	path := s.options.LegacyState
	if path == "" {
		return nil
	}
	if err := protectedAncestors(filepath.Dir(path), s.process.UID); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	uid, _, links, err := ownership(info)
	if err != nil || uid != 0 && uid != s.process.UID || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || links != 1 || info.Size() > 1<<20 {
		return refuse("the legacy snapshot must be a protected administrator or service-owned file\nInstead: freeze the existing live 0.7.0 sessions during service activation.")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if _, err := eventstore.Parse(data, "the legacy activation snapshot"); err != nil {
		return err
	}
	var snapshot LegacySnapshot
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil || snapshot.Config != s.options.Config {
		return refuse("the legacy activation snapshot is invalid or for another configuration")
	}
	hash := sha256.Sum256(data)
	fingerprint := hex.EncodeToString(hash[:]) + "\n"
	marker, err := privateFile(s.store.root, "legacy-imported", 0600)
	if err != nil {
		return err
	}
	defer marker.Close()
	previous, err := io.ReadAll(io.LimitReader(marker, 128))
	if err != nil {
		return err
	}
	if len(previous) != 0 {
		if string(previous) != fingerprint {
			return refuse("the activated legacy snapshot may not be replaced\nInstead: issue a new human-authorized ticket for new supervisor work.")
		}
		return nil
	}
	for _, session := range snapshot.Sessions {
		current, err := processFor(ProcessRef{PID: session.Process.PID, Start: session.Process.Start})
		if err != nil {
			// An exited legacy process gains no replacement identity.
			continue
		}
		if !samePeer(current.Peer, session.Process) || current.UID == s.process.UID {
			return refuse("a legacy snapshot identity disagrees with the kernel")
		}
		target, _, err := caller.Role(s.policy, session.Role)
		if err != nil {
			return refuse("a legacy snapshot role is absent from trusted policy")
		}
		principal := Principal{ID: target.ID, Level: target.Level, Starter: target.Starter}
		if old, exists := s.store.sessions[current.PID]; exists && samePeer(*old.Process, current.Peer) {
			if *old.Principal != principal {
				return refuse("the legacy snapshot conflicts with a registered role")
			}
			continue
		}
		_, err = s.store.append(Record{Op: "register", Actor: principal.ID, Peer: current.Peer, Principal: &principal, Process: &current.Peer}, func(candidate Record) error {
			encoded, err := json.Marshal(candidate)
			if err != nil || len(encoded)+1 > MaxResponseBytes {
				return corrupt("the legacy registration exceeds its record bound")
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	if _, err := fmt.Fprint(marker, fingerprint); err != nil {
		return err
	}
	if err := marker.Sync(); err != nil {
		return err
	}
	directory, err := s.store.root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	s.lastSeq.Store(s.store.seq)
	return directory.Sync()
}
