package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestRawJudgeNames(t *testing.T) {
	cases := []struct {
		name, text string
		want       []string
	}{
		{"valid", "configuration = \"judge-a\"\n", []string{"judge-a"}},
		{"before error", "configuration = 'judge-b'\nbroken = [\n", []string{"judge-b"}},
		{"after error", "broken = [\nconfiguration = \"judge-c\"\n", []string{"judge-c"}},
		{"quoted key", "\"configuration\" = 'judge-d'\nbroken = [\n", []string{"judge-d"}},
		{"multiline value", "configuration = \"\"\"\njudge-e\"\"\"\nbroken = [\n", []string{"judge-e"}},
		{"comment", "# configuration = \"ignored\"\nconfiguration = 'judge-f' # \"\"\"\nbroken = [\n", []string{"judge-f"}},
		{"basic string contents", "note = \"\"\"\nconfiguration = \"ignored\"\n\"\"\"\nconfiguration = 'judge-g'\nbroken = [\n", []string{"judge-g"}},
		{"literal string contents", "note = '''\nconfiguration = \"ignored\"\n'''\nbroken = [\n", nil},
		{"table key", "broken = [\n[nested]\nconfiguration = 'ignored'\n", nil},
		{"array", "array = [\n[1, 2],\n]\nconfiguration = 'judge-h'\nbroken = [\n", []string{"judge-h"}},
		{"not a string", "configuration = 5\n", nil},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			if got := rawJudgeNames([]byte(item.text)); !slices.Equal(got, item.want) {
				t.Fatalf("configuration recovery differs: got=%v want=%v", got, item.want)
			}
		})
	}
}

func TestJudgeSourceBounds(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "regular.toml")
	data := []byte("configuration = 'judge-a'\n")
	if err := os.WriteFile(regular, data, 0600); err != nil {
		t.Fatal(err)
	}
	if got, ok := readJudgeSource(regular); !ok || string(got) != string(data) {
		t.Fatal("regular source bytes must be retained")
	}
	link := filepath.Join(directory, "linked.toml")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	large := filepath.Join(directory, "large.toml")
	if err := os.WriteFile(large, []byte(strings.Repeat("x", 65537)), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, large, directory, filepath.Join(directory, "absent.toml")} {
		if _, ok := readJudgeSource(path); ok {
			t.Fatalf("unavailable, linked or oversized source must not be followed: %s", filepath.Base(path))
		}
	}
}
