package orgtree

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Exercise both managed-file scans and the streaming workspace path. Fixtures
// construct literal canaries at runtime so these tests are safe to scan too.
func scanFileForTest(t *testing.T, mode, name, text string) *tree {
	t.Helper()
	tree := newTree(t.TempDir())
	if mode == "managed" {
		tree.scan(name, text)
	} else {
		if err := os.WriteFile(filepath.Join(tree.root, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		tree.scanWorkspace()
	}
	return tree
}

func checkFileScan(t *testing.T, name, text, rule string) {
	t.Helper()
	for _, mode := range []string{"managed", "workspace"} {
		t.Run(mode, func(t *testing.T) {
			tree := scanFileForTest(t, mode, name, text)
			if rule == "" {
				if len(tree.problems) != 0 {
					t.Fatalf("ordinary source must pass: %v", tree.problems)
				}
				return
			}
			for _, problem := range tree.problems {
				if problem.Path == name && strings.Contains(problem.Message, "secret value detected on line 2 ("+rule+")") {
					return
				}
			}
			t.Fatalf("literal must be flagged by %s on line 2: %v", rule, tree.problems)
		})
	}
}

func tokenAssignment(value string) string {
	return "\n" + "token" + " = " + value + "\n"
}

func literalCanary() string {
	return strings.Join([]string{"hunter2", "literal", "value"}, "-")
}

func TestCodeRefs(t *testing.T) {
	rows := []struct{ name, file, text string }{
		{"self", "project.py", "self.token" + " = token\n"},
		{"getpass", "project.py", "password" + " = options.password if options.password is not None else getpass.getpass(" + strconv.Quote("Password: ") + ")\n"},
		{"go_ref", "project.go", "token" + " := cfg.Token\n"},
		{"go_bare", "project.go", "token" + " := token\n"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) { checkFileScan(t, row.file, row.text, "") })
	}
}

func TestCodeExts(t *testing.T) {
	for _, ext := range strings.Fields("py go js mjs cjs ts jsx tsx java kt rb rs c h cc cpp hpp cs swift scala") {
		t.Run(ext, func(t *testing.T) {
			checkFileScan(t, "project."+ext, tokenAssignment("token"), "")
		})
	}
}

func TestDictRefs(t *testing.T) {
	key := strconv.Quote("password") + ": "
	rows := []struct{ name, text string }{
		{"variable", `{"username": username, ` + key + "password}"},
		{"attribute", `{"username": "route_user", ` + key + "self.password}"},
		{"var_call", "send({" + key + "password})"},
		{"attr_call", "send({" + key + "self.password})"},
		{"var_comma", "{" + key + `password, "username": username}`},
		{"attr_comma", "{" + key + `self.password, "username": username}`},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			checkFileScan(t, "project.py", row.text+"\n", "")
		})
	}
}

func TestSeedFiles(t *testing.T) {
	for _, name := range []string{"client", "test_application"} {
		t.Run(strings.TrimPrefix(name, "test_"), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", "orgscan", name+".py"))
			if err != nil {
				t.Fatal(err)
			}
			checkFileScan(t, name+".py", string(data), "")
		})
	}
}

func TestAllFindings(t *testing.T) {
	literal := tokenAssignment(strconv.Quote(literalCanary()))
	provider := strings.Join([]string{"gh", "p", "_"}, "") + strings.Repeat("a", 30)
	rows := []struct{ name, text, secondRule string }{
		{"double", literal + literal, "secret-assignment"},
		{"no_newline", literal + strings.TrimSuffix(literal, "\n"), "secret-assignment"},
		{"mixed", literal + "\nvalue = " + strconv.Quote(provider) + "\n", "code-host-token"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			for _, mode := range []string{"managed", "workspace"} {
				t.Run(mode, func(t *testing.T) {
					tree := scanFileForTest(t, mode, "project.py", row.text)
					want := []problem{
						{"project.py", "secret value detected on line 2 (secret-assignment); keep secret names only"},
						{"project.py", "secret value detected on line 4 (" + row.secondRule + "); keep secret names only"},
					}
					if !reflect.DeepEqual(tree.problems, want) {
						t.Fatalf("both findings must retain absolute lines and rules: %v", tree.problems)
					}
				})
			}
		})
	}
}

func TestLiteralRows(t *testing.T) {
	value := literalCanary()
	password := strings.Join([]string{"hun", "ter", "2"}, "")
	provider := strings.Join([]string{"gh", "p", "_"}, "") + strings.Repeat("a", 30)
	rows := []struct{ name, file, text, rule string }{
		{"py_quote", "project.py", tokenAssignment(strconv.Quote(value)), "secret-assignment"},
		{"js_raw", "project.js", tokenAssignment("`" + value + "`"), "secret-assignment"},
		{"go_raw", "project.go", tokenAssignment("`" + value + "`"), "secret-assignment"},
		{"py_f", "project.py", tokenAssignment("f" + strconv.Quote(value)), "secret-assignment"},
		{"py_b", "project.py", tokenAssignment("b'" + value + "'"), "secret-assignment"},
		{"py_r", "project.py", tokenAssignment("r" + strconv.Quote(value)), "secret-assignment"},
		{"dict_quote", "project.py", "\n{" + strconv.Quote("password") + ": " + strconv.Quote(value) + "}\n", "secret-assignment"},
		{"env", ".env", "\n" + "PASSWORD" + "=" + password + "\n", "secret-assignment"},
		{"shell", "project.sh", "\n" + "PASSWORD" + "=" + password + "\n", "secret-assignment"},
		{"provider", "project.py", "\nvalue = " + strconv.Quote(provider) + "\n", "code-host-token"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) { checkFileScan(t, row.file, row.text, row.rule) })
	}
}

func TestQuoteForms(t *testing.T) {
	for _, prefix := range []string{"f", "F", "b", "B", "r", "R", "u", "U", "rb", "rB", "Rb", "RB", "br", "bR", "Br", "BR", "rf", "rF", "Rf", "RF", "fr", "fR", "Fr", "FR"} {
		t.Run(prefix, func(t *testing.T) {
			for _, quote := range []string{"'", "\""} {
				checkFileScan(t, "project.py", tokenAssignment(prefix+quote+literalCanary()+quote), "secret-assignment")
			}
		})
	}
	checkFileScan(t, "project.ts", tokenAssignment("`"+literalCanary()+"`"), "secret-assignment")
}

func TestCodePrefixes(t *testing.T) {
	rows := []struct{ name, file, before, after string }{
		{"rust1", "project.rs", "r#\"", "\"#"},
		{"rust2", "project.rs", "r##\"", "\"##"},
		{"rust4", "project.rs", "r####\"", "\"####"},
		{"rust_byte", "project.rs", "br####\"", "\"####"},
		{"cs_at", "project.cs", "@\"", "\""},
		{"cs_dollar", "project.cs", "$\"", "\""},
		{"cs_both", "project.cs", "$@\"", "\""},
		{"cs_reverse", "project.cs", "@$\"", "\""},
		{"swift1", "project.swift", "#\"", "\"#"},
		{"swift5", "project.swift", "#####\"", "\"#####"},
		{"scala_s", "project.scala", "s\"", "\""},
		{"scala_f", "project.scala", "f\"", "\""},
		{"scala_raw", "project.scala", "raw\"", "\""},
		{"id4", "project.scala", "AbCd\"", "\""},
		{"single", "project.py", "q'", "'"},
		{"tagged", "project.js", "tag`", "`"},
		{"cpp_u8", "project.cpp", "u8\"", "\""},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			checkFileScan(t, row.file, tokenAssignment(row.before+literalCanary()+row.after), "secret-assignment")
		})
	}
}

func TestLiteralWrappers(t *testing.T) {
	rows := []struct{ name, file, before, after string }{
		{"paren", "project.py", "(\"", "\")"},
		{"array", "project.py", "[\"", "\"]"},
		{"cast", "project.cs", "(string)\"", "\""},
		{"ptr_cast", "project.c", "(const char *)\"", "\""},
		{"ts_cast", "project.ts", "<string>\"", "\""},
		{"go_cast", "project.go", "string(\"", "\")"},
		{"await", "project.js", "await \"", "\""},
		{"new", "project.js", "new String(\"", "\")"},
		{"plus", "project.rb", "+\"", "\""},
		{"minus", "project.rb", "-\"", "\""},
		{"nested", "project.js", "await (new String((\"", "\")))"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			checkFileScan(t, row.file, tokenAssignment(row.before+literalCanary()+row.after), "secret-assignment")
		})
	}
}

func TestLiteralBounds(t *testing.T) {
	value := literalCanary()
	rows := []struct{ name, file, value string }{
		{"hash_inner", "project.rs", "r##\"!? \"# " + value + "\"##"},
		{"escaped", "project.js", strconv.Quote("\"" + value)},
		{"tick", "project.js", "`\\`" + value + "`"},
		{"verbatim", "project.cs", "@\"!? \"\"" + value + "\"\"\""},
		{"triple_py", "project.py", "\"\"\"" + value + "\"\"\""},
		{"triple_kt", "project.kt", "\"\"\"" + value + "\"\"\""},
		{"triple_sw", "project.swift", "#\"\"\"" + value + "\"\"\"#"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			checkFileScan(t, row.file, tokenAssignment(row.value), "secret-assignment")
		})
	}
	// Closing raw delimiters must end the value, before later code or comments.
	checkFileScan(t, "project.rs", tokenAssignment("r##\"!?\"## + cfg.Token"), "")
	checkFileScan(t, "project.swift", tokenAssignment("#####\"!?\"##### // ordinary note"), "")
	checkFileScan(t, "project.go", tokenAssignment("`\\` + cfg.Token"), "")
}

func TestWrappedRefs(t *testing.T) {
	for index, value := range []string{
		"token", "cfg.Token", "self.password}", "(token)", "[token]", "(string)cfg.Token",
		"<string>cfg.Token", "await cfg.Token", "new Token(cfg.Token)", "+token", "-token",
		`cfg.lookup("name")`, `answer["token"]`, "longer\"" + literalCanary() + "\"",
	} {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			checkFileScan(t, "project.py", tokenAssignment(value), "")
		})
	}
}

func TestNonCodeRows(t *testing.T) {
	for _, name := range []string{".env", "project.sh", "Makefile", "Dockerfile", "project.toml", "project.yaml", "project.yml", "project.ini", "project.properties", "project.conf", "project"} {
		t.Run(strings.TrimPrefix(name, "project."), func(t *testing.T) {
			checkFileScan(t, name, tokenAssignment(literalCanary()), "secret-assignment")
		})
	}
}

func TestPunctuationValues(t *testing.T) {
	for _, value := range []string{")", "()", "!@#", "! ?", "\"\"", "\")", "'! ?'", "`! ?`"} {
		if literalValue(value) || literalQuoted(value) || literalToken(value, false) {
			t.Fatal("a value without letters or digits must not be a literal")
		}
	}
	// Prefix letters describe syntax, not literal content.
	if literalValue("f\"! ?\"") {
		t.Fatal("a prefixed punctuation-only string must not be a literal")
	}
	if !literalQuoted("密碼") || !literalQuoted("１２３") {
		t.Fatal("Unicode letters and digits must still count as literal content")
	}
}

func TestValueScanUnchanged(t *testing.T) {
	text := tokenAssignment(literalCanary())
	if findCredential(text) == nil || !credentialInValue(text) || !credentialInValue(map[string]any{"token": literalCanary()}) {
		t.Fatal("value and message scans must retain the conservative assignment rule")
	}
	if credentialInValue(map[string]any{"password": "! ?"}) {
		t.Fatal("punctuation-only structured values must pass")
	}
}
