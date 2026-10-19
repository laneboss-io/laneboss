package start

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"laneboss.io/laneboss/internal/identityd/ticket"
)

func TestTicketFileGrammar(t *testing.T) {
	o, err := parseArgs([]string{"--config", "example", "--level", "5", "--role", "top", "--ticket-file", "/tmp/registration-ticket"})
	if err != nil || o.ticketFile == nil || *o.ticketFile != "/tmp/registration-ticket" || o.level != 5 {
		t.Fatal("start lost the handoff path")
	}
	for _, args := range [][]string{
		{"--ticket-file", "/tmp/registration-ticket"},
		{"--role", "top", "--ticket-file"},
		{"--role", "top", "--ticket-file", "/tmp/registration-ticket"},
		{"--level", "5", "--level", "4", "--role", "top"},
		{"--level", "5", "--role", "top", "--ticket-file", "/tmp/first", "--ticket-file", "/tmp/second"},
		{"--level", "5", "--role", "top", "--ticket", "private-input-canary"},
	} {
		_, err := parseArgs(args)
		if err == nil || strings.Contains(err.Error(), "private-input-canary") {
			t.Fatal("start admitted an invalid ticket argument or repeated its value")
		}
	}
}

type issueKey struct{}
type fixtureHuman struct{}

func (fixtureHuman) RequireHuman(ctx context.Context) error {
	principal, ok := ctx.Value(issueKey{}).(string)
	if !ok || principal != "terminal-human" {
		return errors.New("the fixture issue context is not authorized")
	}
	return nil
}

type storeRegistrar struct {
	store *ticket.Store
	path  string
	calls int
}

func (r *storeRegistrar) Register(ctx context.Context, scope ticket.Scope, raw string) error {
	r.calls++
	if err := r.store.Consume(ctx, scope, raw); err != nil {
		return err
	}
	// Changing the file after the service received it proves that start uses
	// the single read, rather than returning to the file during rendering.
	return os.WriteFile(r.path, []byte("changed after consumption\n"), 0600)
}

func TestTicketPresentation(t *testing.T) {
	directory := t.TempDir()
	home := filepath.Join(directory, "config")
	states := filepath.Join(directory, "state")
	config := filepath.Join(home, "configs", "example")
	if err := os.MkdirAll(config, 0700); err != nil {
		t.Fatal("cannot prepare the isolated configuration")
	}
	input := "schema_version = 1\nname = \"example\"\n[runners.agent]\ncommand = [\"echo\", \"{brief}\"]\n[supervisors.top]\nlevel = 5\nrunner = \"agent\"\n"
	if err := os.WriteFile(filepath.Join(config, "config.toml"), []byte(input), 0600); err != nil {
		t.Fatal("cannot write the isolated configuration")
	}
	t.Setenv("LANEBOSS_HOME", home)
	t.Setenv("LANEBOSS_STATE_HOME", states)
	t.Setenv("LANEBOSS_CONFIG", "example")
	for _, key := range []string{"LANEBOSS_LANE", "LANEBOSS_ROLE", "LANEBOSS_INSTANCE", "LANEBOSS_SESSION"} {
		if _, set := os.LookupEnv(key); set {
			t.Fatal("the isolated test process must have no live identity labels")
		}
	}
	db, err := sql.Open("sqlite", filepath.Join(directory, "identity.sqlite"))
	if err != nil {
		t.Fatal("cannot open the real ticket database")
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error("cannot close the presentation fixture database")
		}
	})
	store, err := ticket.NewStore(context.Background(), db, fixtureHuman{})
	if err != nil {
		t.Fatal("cannot initialize the real ticket store")
	}
	issue := context.WithValue(context.Background(), issueKey{}, "terminal-human")
	raw, err := store.Issue(issue, ticket.Scope{Config: "example", Level: 5, Role: "top"}, ticket.DefaultTTL)
	if err != nil {
		t.Fatal("cannot issue the presentation fixture")
	}
	path := filepath.Join(directory, "handoff")
	if err := os.WriteFile(path, []byte(raw+"\n"), 0600); err != nil {
		t.Fatal("cannot write the presentation fixture")
	}
	registrar := &storeRegistrar{store: store, path: path}
	args := []string{"--config", "example", "--level", "5", "--role", "top", "--ticket-file", path, "--format", "json"}
	var stdout, stderr bytes.Buffer
	code := RunWithRegistrar(args, nil, &stdout, &stderr, registrar)
	if code != 0 || stdout.Len() == 0 || stderr.Len() != 0 || registrar.calls != 1 {
		t.Fatal("start did not consume the ticket once through the supplied service")
	}
	if strings.Contains(stdout.String()+stderr.String(), raw) {
		t.Fatal("start disclosed the ticket")
	}
	if err := os.WriteFile(path, []byte(raw+"\n"), 0600); err != nil {
		t.Fatal("cannot restore the same ticket for the second use")
	}
	stdout.Reset()
	stderr.Reset()
	code = RunWithRegistrar(args, nil, &stdout, &stderr, registrar)
	if code != 2 || stdout.Len() != 0 || registrar.calls != 2 ||
		!strings.HasPrefix(stderr.String(), "refused: the registration ticket has already been used\nInstead: ") ||
		strings.Contains(stderr.String(), raw) {
		t.Fatal("start did not preserve the real store's single-use refusal without disclosing the ticket")
	}
	if _, err := os.Stat(filepath.Join(states, "example", "sessions")); !os.IsNotExist(err) {
		t.Fatal("start wrote or could not rule out a local session-record fallback")
	}
}
