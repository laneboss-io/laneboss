//go:build linux && laneboss_root_canary

package admin_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
)

func init() {
	if len(os.Args) != 2 || os.Args[1] != "key-store" {
		return
	}
	if err := keyStoreMain(); err != nil {
		os.Stderr.WriteString("key metadata store failed\n")
		os.Exit(89)
	}
	os.Exit(0)
}

type keyClock struct{}

func (keyClock) Now() time.Time { return time.Now() }

// The separate service UID writes real SQLite bytes using the product store.
// The object is comparison evidence, never invented projection authority.
func keyStoreMain() (resultErr error) {
	input := os.NewFile(3, "key-metadata")
	defer func() { resultErr = errors.Join(resultErr, input.Close()) }()
	var selected struct {
		Config   string
		Path     string
		Metadata json.RawMessage
	}
	if err := json.NewDecoder(input).Decode(&selected); err != nil {
		return err
	}
	s, err := store.New(store.Dependencies{Config: selected.Config, Directory: selected.Path, Clock: keyClock{}})
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, s.Close()) }()
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return err
	}
	id := api.ID(hex.EncodeToString(entropy[:]))
	sum := sha256.Sum256(selected.Metadata)
	actor := api.Actor{Kind: "service", ID: "key-service"}
	cause := api.InternalIntent{ID: id, Kind: api.InternalOrgBootstrap, Config: selected.Config, Actor: actor, RequestedBy: actor}
	_, err = s.Transact(context.Background(), api.Transaction{
		Scope: api.Scope{Config: selected.Config, Actor: actor, Source: "worker", PolicyGeneration: 1}, Internal: &cause,
		Writes: api.StateWrites{Objects: []api.ObjectWrite{{ObjectKey: id, Class: "manifest", Bytes: selected.Metadata,
			SHA256: api.Digest(hex.EncodeToString(sum[:])), Origin: "service", ACL: api.ObjectACL{Config: selected.Config, Owner: actor, Audience: "owner", Generation: 1}}}},
	})
	if err != nil {
		return err
	}
	// The service-UID process owns this successful transaction and its real
	// cgroup. Emit only measured size/status, so its actual role journal is
	// searchable even while the readiness handshake uses a separate pipe.
	journal, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: "/run/systemd/journal/socket", Net: "unixgram"})
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, journal.Close()) }()
	message := []byte(fmt.Sprintf("MESSAGE=credential metadata committed bytes=%d\nPRIORITY=6\nSYSLOG_IDENTIFIER=laneboss-key-store\n", len(selected.Metadata)))
	if n, err := journal.Write(message); err != nil || n != len(message) {
		return errors.New("key service journal delivery failed")
	}
	if _, err := os.Stdout.WriteString("stored\n"); err != nil {
		return err
	}
	var hold [1]byte
	if n, err := os.Stdin.Read(hold[:]); n != 0 || !errors.Is(err, io.EOF) {
		return errors.New("key service lifetime control failed")
	}
	return nil
}
