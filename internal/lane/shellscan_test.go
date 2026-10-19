package lane

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/textcontext"
)

func TestTextSubstitutionBoundaries(t *testing.T) {
	for _, row := range []struct {
		name, command string
		want          bool
	}{
		{"ansi-followed-by-code", "python3 $'it\\'s' -c \"print('$(printf fixture)')\"", true},
		{"ansi-literal", "python3 -c $'it\\'s \"$(printf fixture)\"'", false},
		{"continued-opener", "python3 -c \"print('$\\\n(printf fixture)')\"", true},
		{"escaped-continued", "python3 -c \"print('\\$\\\n(printf fixture)')\"", false},
		{"arithmetic", "python3 -c \"print('$((1 + 2))')\"", false},
		{"arithmetic-fallback", "python3 -c \"print('$((printf fixture) )')\"", true},
		{"group-fallback", "python3 -c \"print('$((printf first);(printf second))')\"", true},
		{"nested-out-of-scope", "value=$(printf %s \"`printf fixture`\")", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			got, err := ShellSubstitutionInText(row.command)
			if err != nil || got != row.want {
				t.Fatalf("expansion boundary: got %v, error %v; want %v", got, err, row.want)
			}
		})
	}
}

func TestConfiguredTextArguments(t *testing.T) {
	tools := []textcontext.Tool{{Command: []string{"message-tool", "send"}, TextFrom: 3}}
	for _, row := range []struct {
		command string
		want    bool
	}{
		{"message-tool send recipient \"text $(printf fixture)\"", true},
		{"message-tool send \"$(printf recipient)\" plain", false},
		{"message-tool send recipient --file \"$(printf file)\"", false},
		{"other-tool send recipient \"$(printf fixture)\"", false},
		{"other-tool send recipient \"`printf fixture`\"", true},
	} {
		got, err := ShellSubstitutionInText(row.command, tools)
		if err != nil || got != row.want {
			t.Fatalf("configured argument context: got %v, error %v; want %v", got, err, row.want)
		}
	}
}

func TestLongUnicodeShellWord(t *testing.T) {
	text := strings.Repeat("界", 60000)
	command := "python3 -c \"" + text + " $(printf fixture)\" > result.txt"
	tokens := shellTokens(command)
	if len(tokens) != 5 || tokens[2].text != text+" $(printf fixture)" || !tokens[2].dollar {
		t.Fatal("a long Unicode word lost bytes, boundaries or expansion metadata")
	}
	got, err := ShellSubstitutionInText(command)
	if err != nil || !got {
		t.Fatal("a long code argument lost its actual expansion")
	}
	directory := t.TempDir()
	writes, _ := AnalyseShell(command, directory)
	if !reflect.DeepEqual(writes, []string{filepath.Join(directory, "result.txt")}) {
		t.Fatal("the scanner lost the redirection after a long word")
	}
}

func TestProseAfterGlobalOptions(t *testing.T) {
	tools := []textcontext.Tool{{Command: []string{"prompt-tool", "exec"}, TextFrom: 2, ValueOptions: []string{"--model"}}}
	got, err := ShellSubstitutionInText("prompt-tool --model model-1 exec \"prose $(printf fixture)\"", tools)
	if err != nil || !got {
		t.Fatal("a known global value option must not hide the configured prompt")
	}
	got, err = ShellSubstitutionInText("prompt-tool --model \"$(printf model)\" exec plain", tools)
	if err != nil || got {
		t.Fatal("a global option value must not be mistaken for prompt prose")
	}
	tools = []textcontext.Tool{{Command: []string{"prompt-tool"}, TextFrom: 1, TextOption: "-p", ValueOptions: []string{"--model"}}}
	got, err = ShellSubstitutionInText("prompt-tool --model \"-p$(printf model)\" plain", tools)
	if err != nil || got {
		t.Fatal("a value resembling a text option must not select a prose context")
	}
}

func TestIncompleteHeredocs(t *testing.T) {
	got, err := ShellSubstitutionInText("python3 <<FIRST <<SECOND\nprint('$(printf fixture)')")
	if err != nil || !got {
		t.Fatal("bounded incomplete heredoc input must preserve its expansion without panicking")
	}
}
