package boxguest

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
)

func TestScriptSyntax(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec boxcore.GuestSpec
	}{
		{"plain", boxcore.GuestSpec{}},
		{"quoted", boxcore.GuestSpec{
			Tag:          "sprout/' $ " + "`\n",
			RunID:        "run/' $ " + "`\n",
			OutDir:       "/var/tmp/out' $ " + "`\nline",
			DoneFiles:    []string{"/var/tmp/done' $ " + "`\nline"},
			BusyFiles:    []string{"/var/tmp/busy' $ " + "`\nline"},
			Bucket:       "bucket' $ " + "`\nline",
			ObjectPrefix: "runs/' $ " + "`\nline",
		}},
	} {
		for _, provider := range []string{"aws", "gcp"} {
			t.Run(tc.name+"-"+provider, func(t *testing.T) {
				spec := tc.spec
				spec.Provider = provider
				guest := Renderer{}.Render(spec)
				scripts := map[string]string{
					"startup": guest.Startup, "guard": GuardScript(spec),
				}
				if provider == "gcp" {
					scripts["shutdown"] = guest.Shutdown
				}
				for name, script := range scripts {
					if !strings.HasPrefix(script, "#!/bin/bash\nset -u\n") {
						t.Fatalf("%s lacks bash header and nounset", name)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					cmd := exec.CommandContext(ctx, "bash", "-n")
					cmd.Stdin = strings.NewReader(script)
					output, err := cmd.CombinedOutput()
					cancel()
					if err != nil {
						t.Fatalf("%s syntax: %v\n%s", name, err, output)
					}
				}
			})
		}
	}
}

func TestLiteralPaths(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out' $VALUE "+
		"`printf sprout`\nline")
	h := newGuard(t, boxcore.GuestSpec{
		Provider: "gcp", OutDir: out, Bucket: "sprout-bucket",
		ObjectPrefix: "runs/literal",
	})
	file := h.out("result.txt", "literal body\n", testNow-1)
	find, err := exec.LookPath("find")
	if err != nil {
		t.Fatal(err)
	}
	find, err = filepath.Abs(find)
	if err != nil {
		t.Fatal(err)
	}
	echo := filepath.Join(h.root, "baked-path")
	h.env["FAKE_FIND_LOG"] = echo
	h.fake("find", "printf '%s' \"$1\" > \"$FAKE_FIND_LOG\"\nexec "+
		testQuote(find)+" \"$@\"\n")
	h.execute(testNow, "sync", 0)
	if got := readFile(t, echo); got != out {
		t.Fatalf("baked path %q, want literal %q", got, out)
	}
	uploads := h.uploadsSince(0)
	if len(uploads) != 1 {
		t.Fatalf("got %d literal path uploads", len(uploads))
	}
	checkUpload(t, uploads[0], "sprout-bucket", "runs/literal/out/result.txt",
		file, "literal body\n")
	h.spec.DoneFiles = []string{filepath.Join(h.root, "done' $VALUE "+
		"`printf sprout`\nline")}
	h.spec.BusyFiles = []string{filepath.Join(h.root, "busy' $VALUE "+
		"`printf sprout`\nline")}
	h.write(h.guard, GuardScript(h.spec), 0755)
	h.write(h.spec.BusyFiles[0], "busy\n", 0644)
	h.setTime(h.spec.BusyFiles[0], testNow)
	h.write(filepath.Join(h.run, "idle-since"), "1\n", 0644)
	h.execute(testNow, "", 0)
	h.shutdowns(0)
	absent(t, filepath.Join(h.run, "idle-since"))
	h.write(h.spec.DoneFiles[0], "done\n", 0644)
	h.execute(testNow, "", 0)
	h.shutdowns(1)
}

func TestStartupLayout(t *testing.T) {
	spec := boxcore.GuestSpec{
		Provider: "gcp", Tag: "sprout/a b", OutDir: "/var/tmp/sprout-out",
		HardMin: 17, IdleMin: 3, Bucket: "sprout-bucket",
		ObjectPrefix: "runs/seed", RunID: "seed", SyncSeconds: 71,
	}
	startup := Renderer{}.Render(spec).Startup
	for _, part := range []string{
		"mkdir -p -- '/var/tmp/sprout-out'",
		"chmod 1777 -- '/var/tmp/sprout-out'",
		"if ! shutdown -h '+17' 'sprout_a_b hard cap'; then",
		"logger -t 'sprout_a_b' 'hard cap scheduling failed'",
		"chmod 755 '/usr/local/bin/lb-box-guard'",
		"command -v systemctl", "[ -d '/run/systemd/system' ]",
		"'/etc/systemd/system/sprout_a_b-guard.service'",
		"Type=oneshot", "ExecStart=/usr/local/bin/lb-box-guard",
		"'/etc/systemd/system/sprout_a_b-guard.timer'",
		// Each line is matched whole: 60 must not pass as the start of 600.
		"\nOnBootSec=60\n", "\nOnUnitActiveSec=60\n", "\nAccuracySec=1s\n",
		"WantedBy=timers.target", "systemctl daemon-reload",
		"systemctl enable --now 'sprout_a_b-guard.timer'",
		"'/etc/cron.d/sprout_a_b-guard'",
		"* * * * * root /usr/local/bin/lb-box-guard",
		"chmod 644 '/etc/cron.d/sprout_a_b-guard'",
		"logger -t 'sprout_a_b' 'guard installed:",
	} {
		if !strings.Contains(startup, part) {
			t.Fatalf("startup missing %q", part)
		}
	}
	mkdirAt := strings.Index(startup, "mkdir -p")
	hardAt := strings.Index(startup, "shutdown -h")
	guardAt := strings.Index(startup, "cat > '/usr/local/bin/lb-box-guard'")
	unitsAt := strings.Index(startup, "command -v systemctl")
	if !(mkdirAt < hardAt && hardAt < guardAt && guardAt < unitsAt) {
		t.Fatal("startup phases are out of order")
	}
	body := heredocGuard(t, startup)
	if body != GuardScript(spec) {
		t.Fatal("startup embeds a different guard")
	}
	if strings.Contains(body, "LB_BOX_GUARD_END") {
		t.Fatal("guard contains its heredoc delimiter")
	}
	for _, provider := range []string{"aws", "gcp"} {
		spec.Provider = provider
		if size := len(Renderer{}.Render(spec).Startup); size >= 12000 {
			t.Fatalf("%s startup is %d bytes", provider, size)
		}
	}
}

func heredocGuard(t *testing.T, startup string) string {
	t.Helper()
	const opening = "<<'LB_BOX_GUARD_END'\n"
	at := strings.Index(startup, opening)
	if at < 0 {
		t.Fatal("guard heredoc missing")
	}
	rest := startup[at+len(opening):]
	end := strings.Index(rest, "\nLB_BOX_GUARD_END\n")
	if end < 0 {
		t.Fatal("guard heredoc terminator missing")
	}
	return rest[:end+1]
}

func TestDelimiterData(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out\nLB_BOX_GUARD_END\nline")
	h := newGuard(t, boxcore.GuestSpec{
		Provider: "gcp", Tag: "LB_BOX_GUARD_END", OutDir: out,
		Bucket: "sprout-bucket", ObjectPrefix: "runs/delimiter",
	})
	guard := GuardScript(h.spec)
	if strings.Contains(guard, "LB_BOX_GUARD_END") {
		t.Fatal("data collides with the fixed delimiter")
	}
	if heredocGuard(t, Renderer{}.Render(h.spec).Startup) != guard {
		t.Fatal("delimiter data truncates the embedded guard")
	}
	file := h.out("result.txt", "delimiter body\n", testNow-1)
	h.execute(testNow, "sync", 0)
	uploads := h.uploadsSince(0)
	if len(uploads) != 1 {
		t.Fatalf("got %d uploads", len(uploads))
	}
	checkUpload(t, uploads[0], "sprout-bucket", "runs/delimiter/out/result.txt",
		file, "delimiter body\n")
}

func TestLiteralHarvestValues(t *testing.T) {
	bucket := "sprout' $VALUE " + "`printf seed`\nline"
	prefix := "runs/seed' $VALUE " + "`printf seed`\nline"
	h := newGuard(t, boxcore.GuestSpec{
		Provider: "gcp", Bucket: bucket, ObjectPrefix: prefix, RunID: "seed",
	})
	file := h.out("result.txt", "literal body\n", testNow-1)
	h.execute(testNow, "sync", 0)
	uploads := h.uploadsSince(0)
	if len(uploads) != 1 {
		t.Fatalf("got %d literal value uploads", len(uploads))
	}
	checkUpload(t, uploads[0], bucket, prefix+"/out/result.txt", file, "literal body\n")
}

func TestProviderSeparation(t *testing.T) {
	spec := boxcore.GuestSpec{
		Bucket: "sprout-bucket", ObjectPrefix: "runs/seed", RunID: "seed",
	}
	for _, provider := range []string{"aws", "", "other"} {
		spec.Provider = provider
		guest := Renderer{}.Render(spec)
		for _, forbidden := range []string{
			"sprout-bucket", "metadata.google.internal", "token", "TOKEN",
		} {
			if strings.Contains(guest.Startup, forbidden) ||
				strings.Contains(GuardScript(spec), forbidden) {
				t.Fatalf("%q script contains %q", provider, forbidden)
			}
		}
		if guest.Shutdown != "" {
			t.Fatalf("%q has a shutdown script", provider)
		}
	}
	spec.Provider = "gcp"
	guest := Renderer{}.Render(spec)
	for _, part := range []string{"sprout-bucket", "metadata.google.internal", "access_token"} {
		if !strings.Contains(guest.Startup, part) {
			t.Fatalf("GCP startup lacks %q", part)
		}
	}
	for _, part := range []string{
		"[ ! -f '/usr/local/bin/lb-box-guard' ]", "exit 0",
		"exec timeout 25 '/usr/local/bin/lb-box-guard' 'final'",
	} {
		if !strings.Contains(guest.Shutdown, part) {
			t.Fatalf("GCP shutdown lacks %q", part)
		}
	}
}

func TestRenderDefaults(t *testing.T) {
	guest := Renderer{}.Render(boxcore.GuestSpec{})
	for _, part := range []string{
		"TAG='lb-box'", "IDLE_MIN='30'",
		"OUT_DIR='/var/lib/lb-box/out'",
		"DONE_FILES=('/var/tmp/lb-done')", "BUSY_FILES=('/var/tmp/lb-busy')",
		"RUN=${LB_GUARD_RUN_DIR:-'/run/lb-box'}",
		"shutdown -h '+360' 'lb-box hard cap'",
		"guard installed: idle 30 min, hard 360 min, sync 60 s",
	} {
		if !strings.Contains(guest.Startup, part) {
			t.Fatalf("default startup lacks %q", part)
		}
	}
	h := newGuard(t, boxcore.GuestSpec{})
	h.execute(testNow, "", 0)
	h.execute(testNow+1799, "", 0)
	h.shutdowns(0)
	h.execute(testNow+1800, "", 0)
	h.shutdowns(1)
}

func TestNameReduction(t *testing.T) {
	h := newGuard(t, boxcore.GuestSpec{
		Provider: "gcp", Tag: "sprout/a b", RunID: "Run.9_-/a b'$" + "`\n☃",
		Bucket: "sprout-bucket", ObjectPrefix: "runs/names",
	})
	guest := Renderer{}.Render(h.spec)
	if !strings.Contains(guest.Startup, "'sprout_a_b-guard.timer'") {
		t.Fatal("tag was not reduced for unit names")
	}
	h.execute(testNow, "final", 0)
	uploads := h.uploadsSince(0)
	if len(uploads) != 1 {
		t.Fatalf("got %d final uploads", len(uploads))
	}
	var marker map[string]string
	if err := json.Unmarshal([]byte(uploads[0].body), &marker); err != nil {
		t.Fatal(err)
	}
	if marker["run_id"] != "Run.9_-_a_b_____" {
		t.Fatalf("run id %q", marker["run_id"])
	}
	if !strings.Contains(guest.Startup, "logger -t 'sprout_a_b'") {
		t.Fatal("log tag was not reduced")
	}
}

func TestRenderKeepsSpec(t *testing.T) {
	spec := boxcore.GuestSpec{
		Provider: "gcp", Tag: "sprout/a", RunID: "seed/a",
		DoneFiles: []string{"/var/tmp/z-done", "/var/tmp/a-done"},
		BusyFiles: []string{"/var/tmp/y-busy", "/var/tmp/b-busy"},
		Bucket:    "sprout-bucket", ObjectPrefix: "runs/seed",
	}
	before := spec
	before.DoneFiles = append([]string(nil), spec.DoneFiles...)
	before.BusyFiles = append([]string(nil), spec.BusyFiles...)
	guest := New().Render(spec)
	if !reflect.DeepEqual(spec, before) {
		t.Fatal("render mutates the input")
	}
	for _, part := range []string{
		"DONE_FILES=('/var/tmp/z-done' '/var/tmp/a-done')",
		"BUSY_FILES=('/var/tmp/y-busy' '/var/tmp/b-busy')",
		"TAG='sprout_a'", "RUN_ID='seed_a'", "PREFIX='runs/seed'",
	} {
		if !strings.Contains(guest.Startup, part) {
			t.Fatalf("renderer interface ignored input %q", part)
		}
	}
}
