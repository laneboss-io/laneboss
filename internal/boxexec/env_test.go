package boxexec

import (
	"os"
	"strings"
	"testing"
)

func TestCleanEnv(t *testing.T) {
	for _, key := range []string{
		"AWS_ACCESS_KEY_ID", "GOOGLE_APPLICATION_CREDENTIALS",
		"CLOUDSDK_CONFIG", "SSH_AUTH_SOCK", "TOKEN", "PATH_EXTRA", "HOME_EXTRA",
	} {
		t.Setenv(key, "demo")
	}
	t.Setenv("PATH", "/demo/bin")
	t.Setenv("HOME", "/demo/home")
	for _, key := range []string{"TMPDIR", "LANG", "TERM"} {
		unsetEnv(t, key)
	}
	cases := []struct {
		name  string
		extra map[string]string
		want  []string
	}{
		{"base", nil, []string{"PATH=/demo/bin", "HOME=/demo/home"}},
		{"sorted", map[string]string{"Z": "last", "A": "first"},
			[]string{"PATH=/demo/bin", "HOME=/demo/home", "A=first", "Z=last"}},
		{"invalid", map[string]string{"A=B": "bad", "": "bad"},
			[]string{"PATH=/demo/bin", "HOME=/demo/home"}},
		{"override", map[string]string{"PATH": "/extra/bin", "A": "first"},
			[]string{"PATH=/extra/bin", "HOME=/demo/home", "A=first"}},
		{"empty-value", map[string]string{"PATH": "", "A": ""},
			[]string{"PATH=", "HOME=/demo/home", "A="}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkEnv(t, CleanEnv(tc.extra), tc.want)
		})
	}
}

func TestCleanEnvOrder(t *testing.T) {
	for _, key := range []string{"PATH", "HOME", "TMPDIR", "LANG", "TERM"} {
		t.Setenv(key, "demo")
	}
	got := CleanEnv(map[string]string{"Z": "last", "A": "first", "LANG": "extra"})
	checkEnv(t, got, []string{
		"PATH=demo", "HOME=demo", "TMPDIR=demo", "LANG=extra", "TERM=demo", "A=first", "Z=last",
	})
}

func TestCleanEnvUnset(t *testing.T) {
	for _, key := range []string{"PATH", "HOME", "TMPDIR", "LANG", "TERM"} {
		unsetEnv(t, key)
	}
	if got := CleanEnv(nil); got == nil || len(got) != 0 {
		t.Fatal("unset basic variables must yield a non-nil empty environment")
	}
	checkEnv(t, CleanEnv(map[string]string{"HOME": "demo", "A": "first"}),
		[]string{"A=first", "HOME=demo"})
}

func unsetEnv(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("could not unset %s", key)
	}
}

func checkEnv(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("environment entry count = %d, want %d", len(got), len(want))
	}
	for i, expected := range want {
		key, _, _ := strings.Cut(expected, "=")
		if got[i] != expected {
			t.Fatalf("environment entry differs for %s", key)
		}
	}
}
