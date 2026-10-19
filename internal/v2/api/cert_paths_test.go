package api

import "testing"

func TestRuntimeCertAliases(t *testing.T) {
	base := RuntimeObject{Role: "runtime-cert", Mode: 0444, RelativePath: "etc/ssl/certs/root.pem",
		Aliases: []string{"/etc/ssl/certs/01234567.0"}}
	if !RuntimeAliasesValid(base) {
		t.Fatal("declared certificate file alias was refused")
	}
	for _, name := range []string{"/etc/passwd", "/etc/ssl/certs", "/etc/ssl/certs/", "/etc/ssl/certs/../root.pem",
		"/etc/ssl/certs/sub/root.pem", "/etc/ssl/certs/root.pem", "/etc/ssl/certs/a\x00b"} {
		input := base
		input.Aliases = []string{name}
		if RuntimeAliasesValid(input) {
			t.Fatal("a directory, escape, duplicate or non-certificate alias was admitted")
		}
	}
	for _, change := range []func(*RuntimeObject){
		func(value *RuntimeObject) { value.Mode = 0555 },
		func(value *RuntimeObject) { value.Role = "runtime-library" },
		func(value *RuntimeObject) { value.RelativePath = "usr/bin/tool" },
		func(value *RuntimeObject) { value.Aliases = append(value.Aliases, value.Aliases[0]) },
		func(value *RuntimeObject) { value.Aliases = make([]string, 9) },
	} {
		input := base
		change(&input)
		if RuntimeAliasesValid(input) {
			t.Fatal("certificate alias authorization or its bound was widened")
		}
	}
}
