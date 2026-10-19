//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

type keyHomeEntry struct {
	Mode os.FileMode
	UID  uint32
	GID  uint32
	Data []byte
}

func TestKeyFlagHomes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("flag home comparison requires the root test box")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(base, 0700) != nil {
		t.Fatal("cannot prepare the private comparison root")
	}
	directory := filepath.Join(base, "records")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	records, err := claudock.NewRecords(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer records.Close()
	lease := api.HelperLease{ID: "key-lease", UID: 100001, GID: 100001}
	home := filepath.Join(base, "home")
	for _, path := range []string{home, filepath.Join(home, ".claude")} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, int(lease.UID), int(lease.GID)); err != nil {
			t.Fatal(err)
		}
	}
	if err := claudock.InitializeAllocatedHome(home, records); err != nil {
		t.Fatal(err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	nonce[6] = nonce[6]&0x0f | 0x40
	nonce[8] = nonce[8]&0x3f | 0x80
	id := fmt.Sprintf("%x-%x-%x-%x-%x", nonce[:4], nonce[4:6], nonce[6:8], nonce[8:10], nonce[10:])
	prompt := []byte("Compare private source routes.\n")
	vendor := api.Executable{ID: "claude", Version: "2.1.296", SHA256: digestBytes([]byte("declared vendor fixture"))}
	request := api.RunnerRequest{Target: api.LifeRef{LifeID: "key-life", Run: 1}, LogicalTurnID: "key-turn",
		Session: api.Session{ID: "key-session", HistoryID: "key-history", Driver: api.DriverClaudock, VendorID: id,
			VendorVersion: vendor.Version, HomeID: "key-home", LogicalCWD: "/work/main"},
		Prompt: api.BlobRef{ID: "key-prompt", Class: "prompt", Bytes: int64(len(prompt)), SHA256: digestBytes(prompt)},
		Home:   api.PrivateHome{ID: "key-home", WorkspaceID: "key-work", HistoryID: "key-history", VendorDirectory: ".claude"},
		Slot: api.CredentialSlot{ID: "key-slot", ProfileGrantID: "key-grant", ProfileID: "key-profile", LeaseID: "key-lease",
			Mode: "claude-api-key", ExpiresAt: api.Timestamp(time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))},
		Executable: api.Executable{ID: "claudock", Version: "0.1.0", SHA256: digestBytes([]byte("declared wrapper fixture"))},
		Model:      "claude-sonnet-4-6", Effort: "high",
		Budget: api.Budget{WallMS: 60000, MemoryBytes: 1 << 28, Processes: 32, DiskBytes: 1 << 30, Currency: "USD"}}
	plan := claudock.HomePlanRequest{Request: request, Home: api.PrivateHomeBinding{LifeID: request.Target.LifeID,
		Home: request.Home, RootID: "key-root", Generation: 1}, ReservationID: "key-plan", InputsSHA256: digestBytes(prompt),
		Start: true, Claude: vendor, ClaudePath: "/runtime/claude"}
	if err := claudock.PlanPrivateHome(home, records, plan, func(findings []claudock.Finding) error {
		if len(findings) != 0 {
			t.Fatal("comparison home has unexpected findings")
		}
		return nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	checkKeyRoutes(t, home, lease)
}

// The production planner supplies the same credential-free starting home
// for both flag routes. Only in-memory observations are compared; no credential
// home, snapshot or key is copied to a worktree or evidence directory.
func checkKeyRoutes(t *testing.T, home string, lease api.HelperLease) {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-I", "-B", "../../../scripts/v2-serve/key_route.py", "--both")
	cmd.ExtraFiles, cmd.Stdout, cmd.Stderr = []*os.File{write}, io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		write.Close()
		t.Fatal("cannot start the two flag sources")
	}
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(io.LimitReader(read, 2*claudock.MaxAPIKeyBytes+9))
	defer clear(raw)
	if waitErr := cmd.Wait(); err != nil || waitErr != nil {
		t.Fatal("flag sources did not deliver their private descriptors")
	}
	var sources [][]byte
	remaining := raw
	for len(remaining) >= 4 && len(sources) < 2 {
		size := int(binary.BigEndian.Uint32(remaining[:4]))
		remaining = remaining[4:]
		if size < 8 || size > claudock.MaxAPIKeyBytes || size > len(remaining) {
			t.Fatal("flag source frame exceeds its private bound")
		}
		sources = append(sources, remaining[:size])
		remaining = remaining[size:]
	}
	if len(sources) != 2 || len(remaining) != 0 || bytes.Equal(sources[0], sources[1]) {
		t.Fatal("flag sources did not supply two distinct complete fake keys")
	}
	root, err := os.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var baseline map[string]keyHomeEntry
	for _, key := range sources {
		if !bytes.HasPrefix(key, []byte("sk-ant-api03-")) {
			t.Fatal("flag route did not use the vendor-compatible fake key shape")
		}
		parent, name, err := credentialParent(root, claudock.KeyStorePath, lease.UID, lease.GID, 0700)
		if err != nil {
			t.Fatal(err)
		}
		fd, err := reserveCredentialFile(parent, name, 0600)
		if err != nil {
			parent.Close()
			t.Fatal(err)
		}
		output := os.NewFile(uintptr(fd), "private-route-store")
		inputFD, err := unix.MemfdCreate("private-route-source", unix.MFD_CLOEXEC)
		if err != nil {
			t.Fatal(err)
		}
		input := os.NewFile(uintptr(inputFD), "private-route-source")
		if err := unix.Fchmod(inputFD, 0600); err != nil {
			t.Fatal(err)
		}
		if n, err := input.Write(key); err != nil || n != len(key) {
			t.Fatal("cannot supply the private flag source")
		}
		if err := copyKeyStore(ctx, input, output, int64(len(key))); err != nil {
			t.Fatal(err)
		}
		if err := input.Close(); err != nil {
			t.Fatal(err)
		}
		if err := unix.Fchown(fd, int(lease.UID), int(lease.GID)); err != nil {
			t.Fatal(err)
		}
		if err := unix.Fchmod(fd, 0600); err != nil {
			t.Fatal(err)
		}
		observed := keyHomeBytes(t, home, key)
		if baseline == nil {
			baseline = observed
		} else if !reflect.DeepEqual(baseline, observed) {
			t.Fatal("flag routes produced different home bytes or private ownership apart from the key")
		}
		if err := unix.Unlinkat(int(parent.Fd()), name, 0); err != nil {
			t.Fatal(err)
		}
		var links unix.Stat_t
		if err := unix.Fstat(fd, &links); err != nil || links.Nlink != 0 {
			t.Fatal("flag store retained a linked credential inode")
		}
		if err := output.Close(); err != nil {
			t.Fatal(err)
		}
		if err := parent.Close(); err != nil {
			t.Fatal(err)
		}
	}
	t.Log("both CLI flags: complete home bytes, paths, modes and owners identical apart from selected key; no key output")
}

func keyHomeBytes(t *testing.T, home string, key []byte) map[string]keyHomeEntry {
	t.Helper()
	result := map[string]keyHomeEntry{}
	err := filepath.WalkDir(home, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(home, path)
		if err != nil {
			return err
		}
		var native unix.Stat_t
		if err := unix.Lstat(path, &native); err != nil {
			return err
		}
		if !entry.IsDir() && native.Mode&unix.S_IFMT != unix.S_IFREG {
			t.Fatal("flag home contains an unexpected linked or special entry")
		}
		value := keyHomeEntry{Mode: os.FileMode(native.Mode), UID: native.Uid, GID: native.Gid}
		if !entry.IsDir() {
			value.Data, err = os.ReadFile(path)
			if err != nil {
				return err
			}
			if relative == claudock.KeyStorePath {
				actual, err := claudock.DecodeKeyStore(value.Data)
				if err != nil || !bytes.Equal(actual, key) || native.Nlink != 1 || native.Mode&07777 != 0600 {
					t.Fatal("flag home store differs from its exact selected key or private mode")
				}
				clear(actual)
				redacted := bytes.ReplaceAll(value.Data, key, []byte("selected-slot-key"))
				clear(value.Data)
				value.Data = redacted
			} else if bytes.Contains(value.Data, key) || bytes.Contains([]byte(relative), key) {
				t.Fatal("flag home copied its key outside the selected store")
			}
		}
		result[relative] = value
		return nil
	})
	if err != nil {
		t.Fatal("cannot inspect the exact private flag home")
	}
	return result
}
