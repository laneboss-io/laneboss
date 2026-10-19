package installation

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/identity"
)

func newInstallFixture(t *testing.T) (root, prefix, binary string) {
	t.Helper()
	directory := t.TempDir()
	root = filepath.Join(directory, "source")
	prefix = filepath.Join(directory, "prefix")
	binary = filepath.Join(directory, "launcher")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("launcher fixture\n"), 0755); err != nil {
		t.Fatal(err)
	}
	return root, prefix, binary
}

func checkInstalledDiscordAssets(t *testing.T, present []string) {
	t.Helper()
	root, prefix, binary := newInstallFixture(t)
	program, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	wantFiles := map[string][]byte{"bin/" + identity.Program: program}
	for _, relative := range present {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		data := []byte("fixture for " + relative + "\n")
		// Executable source assets must still be installed with mode 0644.
		if err := os.WriteFile(path, data, 0755); err != nil {
			t.Fatal(err)
		}
		wantFiles[relative] = data
	}
	var output bytes.Buffer
	if err := Install(root, prefix, binary, &output); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(prefix, "share", identity.Program, "versions", identity.Version)
	for _, relative := range []string{"integrations/discord/gateway.mjs", "docs/org-discord.md"} {
		path := filepath.Join(target, filepath.FromSlash(relative))
		info, err := os.Lstat(path)
		want, present := wantFiles[relative]
		if !present {
			if !os.IsNotExist(err) {
				t.Fatalf("absent source asset %s was installed or could not be checked: %v", relative, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0644 {
			t.Fatalf("%s installed with mode %v; want a regular file with mode 0644", relative, info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, want) {
			t.Fatalf("%s installed with bytes %q; want %q", relative, data, want)
		}
	}
	names := make([]string, 0, len(wantFiles))
	for name := range wantFiles {
		names = append(names, name)
	}
	sort.Strings(names)
	var wantManifest strings.Builder
	fmt.Fprintf(&wantManifest, "version %s\n", identity.Version)
	for _, name := range names {
		fmt.Fprintf(&wantManifest, "%x  %s\n", sha256.Sum256(wantFiles[name]), name)
	}
	manifest, err := os.ReadFile(filepath.Join(target, "MANIFEST"))
	if err != nil {
		t.Fatal(err)
	}
	if string(manifest) != wantManifest.String() {
		t.Fatalf("MANIFEST = %q; want %q", manifest, wantManifest.String())
	}
}

func TestInstallWithoutDiscordAssets(t *testing.T) {
	checkInstalledDiscordAssets(t, nil)
}

func TestInstallWithDiscordAssets(t *testing.T) {
	for _, test := range []struct {
		name    string
		present []string
	}{
		{"both", []string{"integrations/discord/gateway.mjs", "docs/org-discord.md"}},
		{"gateway-only", []string{"integrations/discord/gateway.mjs"}},
		{"guide-only", []string{"docs/org-discord.md"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			checkInstalledDiscordAssets(t, test.present)
		})
	}
}

func TestInstallRejectsGatewaySymlink(t *testing.T) {
	for _, name := range []string{"existing-target", "missing-target"} {
		t.Run(name, func(t *testing.T) {
			root, prefix, binary := newInstallFixture(t)
			source := filepath.Join(root, "integrations", "discord", "gateway.mjs")
			if err := os.MkdirAll(filepath.Dir(source), 0755); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(root, "gateway-target.mjs")
			if name == "existing-target" {
				if err := os.WriteFile(target, []byte("gateway fixture\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(target, source); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			err := Install(root, prefix, binary, &output)
			want := "cannot read Discord gateway asset integrations/discord/gateway.mjs: source file is not a regular file: " + source
			if err == nil || err.Error() != want {
				t.Fatalf("symlink install error = %v; want %q", err, want)
			}
			if output.Len() != 0 {
				t.Fatalf("refused install produced success output: %q", output.String())
			}
			if _, err := os.Lstat(prefix); !os.IsNotExist(err) {
				t.Fatalf("refused install created its prefix or could not be checked: %v", err)
			}
		})
	}
}
