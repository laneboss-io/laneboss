package orghook

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyDenyRootCoversSubtree(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "protected", "nested", "file.txt")
	if err := os.MkdirAll(filepath.Dir(child), 0700); err != nil {
		t.Fatal(err)
	}
	row := blacklistRule{id: "legacy-root", band: "refuse", pathRoots: []string{filepath.Join(root, "protected")}}
	matched, err := blacklistMatches(row, &instance{}, action{}, []fileEffect{{word: child, directory: "/"}}, nil, nil, nil, "/")
	if err != nil || !matched {
		t.Fatalf("legacy deny root must cover a descendant: matched=%v err=%v", matched, err)
	}
}

func TestLegacyDenyHardlinkAlias(t *testing.T) {
	root := t.TempDir()
	protected := filepath.Join(root, "protected", "source.txt")
	alias := filepath.Join(root, "worktree", "alias.txt")
	if err := os.MkdirAll(filepath.Dir(protected), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(alias), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(protected, []byte("fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(protected, alias); err != nil {
		t.Fatal(err)
	}
	inst := &instance{home: filepath.Join(root, ".laneboss"), directory: root}
	row := blacklistRule{id: "legacy-root", band: "refuse", pathRoots: []string{filepath.Join(root, "protected")}}
	matched, err := blacklistMatches(row, inst, action{}, []fileEffect{{word: alias, directory: root}}, nil, nil, nil, root)
	if err == nil || matched {
		t.Fatalf("a hardlink alias under the org must remain uncheckable: matched=%v err=%v", matched, err)
	}
}

func TestLegacySecretPathStrict(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "shared", "secrets", "api.env")
	if err := os.MkdirAll(filepath.Dir(secret), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("redacted fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	inst := &instance{home: filepath.Join(root, ".laneboss"), directory: root}
	row := blacklistRule{id: "legacy-secret", band: "refuse", legacySecret: true, secretNames: []string{"shared/secrets/api.env"}}
	matched, err := blacklistMatches(row, inst, action{}, nil, []fileEffect{{word: "shared/secrets/api.env", directory: root}}, nil, nil, root)
	if err != nil || !matched {
		t.Fatalf("legacy secret path must use secret-read helpers: matched=%v err=%v", matched, err)
	}
}
