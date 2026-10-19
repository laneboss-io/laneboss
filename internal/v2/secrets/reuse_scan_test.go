package secrets

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func reuseScanFixture(t *testing.T) (api.SecretMaterial, APIKeyScanInputs) {
	t.Helper()
	material := api.SecretMaterial{Bytes: []byte("sk-ant-")}
	material.Bytes = append(material.Bytes, []byte(digestFixture(string(syntheticBytes(t, 48))))...)
	t.Cleanup(func() { clear(material.Bytes) })
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(filepath.Join(home, ".config", "claudock"), 0700); err != nil {
		t.Fatal("cannot allocate scanner home")
	}
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0700); err != nil {
		t.Fatal("cannot allocate scanner Claude directory")
	}
	info, err := os.Lstat(home)
	if err != nil {
		t.Fatal("cannot pin scanner home")
	}
	helper := filepath.Join(root, "helper")
	if err := os.WriteFile(helper, []byte("helper state\n"), 0600); err != nil {
		t.Fatal("cannot retain scanner helper state")
	}
	return material, APIKeyScanInputs{Home: home, HomeIdentity: info, HelperState: helper, Evidence: t.TempDir(),
		Journal: func(context.Context, string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("unit started\n")), nil
		}}
}

func TestReuseScannerPlants(t *testing.T) {
	for place := range reusePlaces {
		for _, kind := range []string{"key", "last8"} {
			t.Run(reusePlaces[place]+"/"+kind, func(t *testing.T) {
				material, inputs := reuseScanFixture(t)
				clean := ScanAPIKeyReleaseInputs(context.Background(), material, inputs)
				if !clean.Clean() {
					t.Fatal("scanner failed its clean control", clean.Line())
				}
				plant := material.Bytes
				if kind == "last8" {
					plant = plant[len(plant)-8:]
				}
				plant = append(append([]byte("prefix\n"), plant...), []byte("\nsuffix")...)
				defer clear(plant)
				paths := []string{filepath.Join(inputs.Home, "retained"), filepath.Join(inputs.Home, ".claude", "config"),
					filepath.Join(inputs.Home, ".config", "claudock", "profiles.json"), filepath.Join(inputs.Home, ".config", "claudock", "credential-store.json"),
					inputs.HelperState, filepath.Join(inputs.Evidence, "retained")}
				if place < 6 {
					if err := os.WriteFile(paths[place], plant, 0600); err != nil {
						t.Fatal("cannot plant scanner control")
					}
				} else {
					role := []string{"service", "helper", "credential"}[place-6]
					inputs.Journal = func(_ context.Context, selected string) (io.ReadCloser, error) {
						if selected == role {
							return io.NopCloser(bytes.NewReader(plant)), nil
						}
						return io.NopCloser(strings.NewReader("unit started\n")), nil
					}
				}
				result := ScanAPIKeyReleaseInputs(context.Background(), material, inputs)
				if result.Clean() || !result[place].Last8 || (kind == "key" && !result[place].Key) || (kind == "last8" && result[place].Key) || result[place].Unreadable {
					t.Fatal("scanner missed its planted-material control", result.Line())
				}
				// The original fixed verdict tokens remain bounded; quoted native
				// path diagnostics follow them and can be longer than one token.
				for _, token := range strings.Fields(result.Line())[:len(reusePlaces)+1] {
					if len(token) >= 40 {
						t.Fatal("scan line contains an oversized token")
					}
				}
				if bytes.Contains([]byte(result.Line()), material.Bytes[len(material.Bytes)-8:]) {
					t.Fatal("scan line contains credential material")
				}
			})
		}
	}
}

type reuseBadClose struct{ io.Reader }

func (reuseBadClose) Close() error { return errors.New("private query failure") }

func TestReuseScannerUnknowns(t *testing.T) {
	for _, fault := range []string{"home", "identity", "helper", "evidence", "journal-open", "journal-read", "journal-close", "journal-empty", "journal-space", "permission", "directory", "root-link", "ancestor-link", "cancelled", "short-key"} {
		t.Run(fault, func(t *testing.T) {
			material, inputs := reuseScanFixture(t)
			switch fault {
			case "home":
				inputs.Home += "-absent"
			case "identity":
				inputs.HomeIdentity = nil
			case "helper":
				inputs.HelperState += "-absent"
			case "evidence":
				inputs.Evidence += "-absent"
			case "journal-open":
				inputs.Journal = func(context.Context, string) (io.ReadCloser, error) { return nil, os.ErrPermission }
			case "journal-read":
				inputs.Journal = func(context.Context, string) (io.ReadCloser, error) { return io.NopCloser(reuseBadRead{}), nil }
			case "journal-close":
				inputs.Journal = func(context.Context, string) (io.ReadCloser, error) {
					return reuseBadClose{strings.NewReader("unit started")}, nil
				}
			case "journal-empty", "journal-space":
				value := ""
				if fault == "journal-space" {
					value = " \n\t"
				}
				inputs.Journal = func(context.Context, string) (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader(value)), nil
				}
			case "permission", "directory":
				path := filepath.Join(inputs.Home, "unreadable")
				if fault == "directory" {
					if os.Mkdir(path, 0000) != nil {
						t.Fatal("cannot plant unreadable directory")
					}
				} else if os.WriteFile(path, []byte("hidden"), 0000) != nil {
					t.Fatal("cannot plant unreadable file")
				}
				t.Cleanup(func() {
					if os.Chmod(path, 0700) != nil {
						t.Error("cannot collect unreadable control")
					}
				})
			case "root-link", "ancestor-link":
				link := filepath.Join(t.TempDir(), "alias")
				target := inputs.Home
				if fault == "ancestor-link" {
					target = filepath.Dir(inputs.Home)
				}
				if os.Symlink(target, link) != nil {
					t.Fatal("cannot plant linked scope")
				}
				inputs.Home = link
				if fault == "ancestor-link" {
					inputs.Home = filepath.Join(link, "home")
				}
			case "short-key":
				material.Bytes = material.Bytes[:7]
			}
			ctx := context.Background()
			if fault == "cancelled" {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			result := ScanAPIKeyReleaseInputs(ctx, material, inputs)
			if result.Clean() || result.FirstHit() == "" {
				t.Fatal("unknown scan input was accepted as clean")
			}
		})
	}
}

type reuseBadRead struct{}

func (reuseBadRead) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestReuseScannerBoundary(t *testing.T) {
	material, inputs := reuseScanFixture(t)
	data := append(bytes.Repeat([]byte("x"), 64*1024+len(material.Bytes)-3), material.Bytes...)
	defer clear(data)
	if os.WriteFile(filepath.Join(inputs.Home, "boundary"), data, 0600) != nil {
		t.Fatal("cannot plant boundary control")
	}
	result := ScanAPIKeyReleaseInputs(context.Background(), material, inputs)
	if result.Clean() || !result[0].Key || !result[0].Last8 {
		t.Fatal("streaming scanner missed a read boundary")
	}
}
