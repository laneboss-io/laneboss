package boxgcp

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

const fenceName = "lb-spot-demo"

// fenceOptions use a mixed-case prefix, so a pass also proves the prefix is lower-cased before it is compared.
func fenceOptions() Options {
	o := testOptions()
	o.NamePrefix = "LB-Spot-"
	return o
}

// ourLabels are the labels the provider puts on a box it launches, as the live instance reports them.
func ourLabels() map[string]string {
	return map[string]string{
		"managed-by": "laneboss", "lb-org": "example-org", "lb-owner": "demo-owner",
		"lb-lane": "demo-lane", "lb-run": "demo-run", "lb-purpose": "demo-purpose",
	}
}

// fenceBox is the box a caller hands in: the name it asks for and, when it knows it, the run.
func fenceBox(name, run string) boxcore.Box {
	b := testBox()
	b.ID, b.Name = name, name
	if run != "" {
		b.Labels = map[string]string{"lb-run": run}
	}
	return b
}

// fenceFake answers every describe with describe(n), n counting the earlier describes, and every other call
// with success. A guarded call that should not happen is therefore recorded and succeeds, so a negative row
// can only pass because the fence refused, never because the fake failed for some other reason.
func fenceFake(describe func(n int) (boxexec.Result, error)) *boxexec.Fake {
	return &boxexec.Fake{Handlers: []boxexec.Handler{
		{Name: "gcloud", ArgsContain: []string{"instances describe"},
			Respond: func(_ boxexec.Cmd, n int) (boxexec.Result, error) { return describe(n) }},
		{Name: "gcloud"},
	}}
}

// always answers every describe with the same result.
func always(result boxexec.Result) func(int) (boxexec.Result, error) {
	return func(int) (boxexec.Result, error) { return result, nil }
}

// verbs names each recorded call by what it does, in order: describe, delete, ssh or rsync. Any other call (a
// stop, a list, anything new) is named by its first two words, so a comparison fails on it.
func verbs(f *boxexec.Fake) []string {
	var out []string
	for _, call := range f.Calls {
		verb := strings.Join(call.Args[:min(2, len(call.Args))], " ")
		for _, known := range []string{"describe", "delete", "ssh", "rsync"} {
			if slices.Contains(call.Args, known) {
				verb = known
			}
		}
		out = append(out, verb)
	}
	return out
}

func requireVerbs(t *testing.T, f *boxexec.Fake, want ...string) {
	t.Helper()
	if got := verbs(f); !slices.Equal(got, want) {
		t.Fatalf("recorded calls = %q, want %q", got, want)
	}
}

// outcome is what one guarded call returned: the exit status (Exec) or file count (FetchHarvest), and the error.
type outcome struct {
	n   int
	err error
}

// fenceAction is one guarded entry point of the provider.
type fenceAction struct {
	name, op string
	refused  int      // the int a refused call returns: -1 from Exec
	granted  []string // the calls a passing instance leads to, in order
	arg      string   // an argument only the guarded call carries
	run      func(t *testing.T, p boxcore.Provider, b boxcore.Box) []outcome
}

func fenceActions() []fenceAction {
	ctx := context.Background()
	return []fenceAction{
		{"teardown", "teardown", 0, []string{"describe", "delete"}, "--delete-disks=all",
			func(t *testing.T, p boxcore.Provider, b boxcore.Box) []outcome {
				return []outcome{{0, p.Teardown(ctx, b)}}
			}},
		{"exec", "ssh", -1, []string{"describe", "ssh", "ssh"}, "--command=echo demo",
			func(t *testing.T, p boxcore.Provider, b boxcore.Box) []outcome {
				// Two commands on one transport: the first one's verdict governs the second.
				tr := p.Transport(b, boxcore.TransportOptions{})
				var out []outcome
				for range 2 {
					code, err := tr.Exec(ctx, "echo demo", nil, nil, nil)
					out = append(out, outcome{code, err})
				}
				return out
			}},
		{"harvest", "fetch-harvest", 0, []string{"describe", "rsync"}, "gs://demo-results/runs/demo-run/out",
			func(t *testing.T, p boxcore.Provider, b boxcore.Box) []outcome {
				count, err := p.FetchHarvest(ctx, b, "demo-run", t.TempDir())
				return []outcome{{count, err}}
			}},
	}
}

// requireRefusal wants a denial from op that names exactly the failed checks and shows no name or label value.
func requireRefusal(t *testing.T, err error, op, failed string, secrets []string) {
	t.Helper()
	e, ok := err.(*boxcore.Error)
	if !ok || e.Kind != boxcore.KindDenied || e.Op != op {
		t.Fatalf("error = %v, want a denial from %s", err, op)
	}
	if want := "box ownership check failed: " + failed; e.Detail != want {
		t.Fatalf("detail = %q, want %q", e.Detail, want)
	}
	var text strings.Builder
	for chain := err; chain != nil; chain = errors.Unwrap(chain) {
		text.WriteString(chain.Error() + "\n")
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(text.String(), secret) {
			t.Fatalf("denial shows %q: %s", secret, text.String())
		}
	}
}

// decoy is a live instance that is not ours, or not provably ours, and the checks that must catch it.
type decoy struct {
	name        string
	live, asked string            // the live name and the requested one: "" is fenceName, and the live name
	run         string            // the lb-run label the caller knows
	emptyPrefix bool              // the configured prefix is empty
	bare        bool              // the live instance has no labels at all
	drop        []string          // labels the live instance lacks
	set         map[string]string // labels it carries with another value
	failed      string            // the checks the denial must name, and no others
}

func (d decoy) labels() map[string]string {
	if d.bare {
		return nil
	}
	labels := ourLabels()
	for _, key := range d.drop {
		delete(labels, key)
	}
	maps.Copy(labels, d.set)
	return labels
}

// TestFenceDecoys: every guarded call refuses a machine that is not provably ours, after reading it and before acting.
func TestFenceDecoys(t *testing.T) {
	rows := []decoy{
		{name: "other-name", live: "decoy-vm", failed: "name prefix"},
		{name: "no-labels", bare: true, failed: "label managed-by missing, label lb-org missing, " +
			"label lb-owner missing, label lb-lane missing, label lb-run missing"},
		{name: "no-managed-by", drop: []string{"managed-by"}, failed: "label managed-by missing"},
		{name: "no-lb-org", drop: []string{"lb-org"}, failed: "label lb-org missing"},
		{name: "no-lb-owner", drop: []string{"lb-owner"}, failed: "label lb-owner missing"},
		{name: "no-lb-lane", drop: []string{"lb-lane"}, failed: "label lb-lane missing"},
		{name: "no-lb-run", drop: []string{"lb-run"}, failed: "label lb-run missing"},
		{name: "empty-lb-lane", set: map[string]string{"lb-lane": ""}, failed: "label lb-lane missing"},
		{name: "other-managed-by", set: map[string]string{"managed-by": "decoy-tool"}, failed: "label managed-by differs"},
		{name: "other-org", set: map[string]string{"lb-org": "decoy-org"}, failed: "label lb-org differs"},
		{name: "live-name-differs", live: "lb-spot-other", asked: fenceName, failed: "name differs"},
		{name: "other-run", run: "decoy-run", failed: "label lb-run differs"},
		// Comparisons are exact: a case variant or an extension of our value is not our value.
		{name: "managed-by-case", set: map[string]string{"managed-by": "Laneboss"}, failed: "label managed-by differs"},
		{name: "managed-by-longer", set: map[string]string{"managed-by": "laneboss-x"}, failed: "label managed-by differs"},
		{name: "org-case", set: map[string]string{"lb-org": "Example-Org"}, failed: "label lb-org differs"},
		{name: "org-longer", set: map[string]string{"lb-org": "example-org-2"}, failed: "label lb-org differs"},
		{name: "run-case", run: "Demo-Run", failed: "label lb-run differs"},
		{name: "name-case", live: "LB-SPOT-DEMO", failed: "name prefix"},
		// An empty prefix would accept every name.
		{name: "empty-prefix", emptyPrefix: true, failed: "name prefix empty"},
	}
	for _, d := range rows {
		t.Run(d.name, func(t *testing.T) {
			live := cmp.Or(d.live, fenceName)
			asked := cmp.Or(d.asked, live)
			row := instanceJSON(t, live, "RUNNING", d.labels(), "")
			secrets := []string{"decoy-vm", live, asked, d.run}
			for _, value := range d.labels() {
				secrets = append(secrets, value)
			}
			for _, a := range fenceActions() {
				t.Run(a.name, func(t *testing.T) {
					o := fenceOptions()
					if d.emptyPrefix {
						o.NamePrefix = ""
					}
					f := fenceFake(always(boxexec.Result{Stdout: row}))
					for _, got := range a.run(t, New(testConfig(), f, o), fenceBox(asked, d.run)) {
						if got.n != a.refused {
							t.Fatalf("refused call returned %d, want %d", got.n, a.refused)
						}
						requireRefusal(t, got.err, a.op, d.failed, secrets)
					}
					// The fence read the machine; nothing was deleted, reached over ssh or harvested, and a later
					// command on the same transport was refused without another read.
					requireVerbs(t, f, "describe")
				})
			}
		})
	}
}

// TestFencePasses: a machine of ours is read first and then acted on, once per transport.
func TestFencePasses(t *testing.T) {
	row := instanceJSON(t, fenceName, "RUNNING", ourLabels(), "")
	for _, run := range []string{"", "demo-run"} {
		known := "unknown-run"
		if run != "" {
			known = "known-run"
		}
		for _, a := range fenceActions() {
			t.Run(a.name+"-"+known, func(t *testing.T) {
				f := fenceFake(always(boxexec.Result{Stdout: row}))
				for _, got := range a.run(t, New(testConfig(), f, fenceOptions()), fenceBox(fenceName, run)) {
					if got.err != nil || got.n != 0 {
						t.Fatalf("a box of ours was refused: n=%d err=%v", got.n, got.err)
					}
				}
				// The read comes first and is the only one: the guarded call follows it, and a second command on
				// the same transport is not read again.
				requireVerbs(t, f, a.granted...)
				requireArgs(t, f.Calls[0].Args, []string{
					"compute", "instances", "describe", fenceName, "--zone=demo-zone-a",
					"--format=json", "--project=demo-project", "--quiet",
				})
				if guarded := f.Calls[len(f.Calls)-1]; !slices.Contains(guarded.Args, a.arg) {
					t.Fatalf("guarded call lacks %q: %q", a.arg, guarded.Args)
				}
			})
		}
	}
	t.Run("two-transports", func(t *testing.T) {
		// A pass belongs to the transport that earned it: another transport reads the machine again.
		f := fenceFake(always(boxexec.Result{Stdout: row}))
		p := New(testConfig(), f, fenceOptions())
		for range 2 {
			tr := p.Transport(fenceBox(fenceName, ""), boxcore.TransportOptions{})
			if code, err := tr.Exec(context.Background(), "echo demo", nil, nil, nil); err != nil || code != 0 {
				t.Fatalf("exec = %d, %v", code, err)
			}
		}
		requireVerbs(t, f, "describe", "ssh", "describe", "ssh")
	})
}

// TestFenceGoneAndErrors: a machine that is gone is no denial, and a read that fails lets nothing act.
func TestFenceGoneAndErrors(t *testing.T) {
	ctx := context.Background()
	row := instanceJSON(t, fenceName, "RUNNING", ourLabels(), "")
	gone := boxexec.Result{Code: 1, Stderr: []byte(goneText("demo-zone-a", fenceName))}
	t.Run("gone-teardown", func(t *testing.T) {
		f := fenceFake(always(gone))
		if err := New(testConfig(), f, fenceOptions()).Teardown(ctx, fenceBox(fenceName, "")); err != nil {
			t.Fatalf("teardown of a gone machine: %v", err)
		}
		requireVerbs(t, f, "describe")
	})
	t.Run("gone-harvest", func(t *testing.T) {
		// Only the results bucket is read, so the harvest proceeds.
		f := fenceFake(always(gone))
		count, err := New(testConfig(), f, fenceOptions()).FetchHarvest(ctx, fenceBox(fenceName, ""), "demo-run", t.TempDir())
		if err != nil || count != 0 {
			t.Fatalf("harvest of a gone machine = %d, %v", count, err)
		}
		requireVerbs(t, f, "describe", "rsync")
		if !slices.Contains(f.Calls[1].Args, "gs://demo-results/runs/demo-run/out") {
			t.Fatalf("rsync source is wrong: %q", f.Calls[1].Args)
		}
	})
	t.Run("gone-exec", func(t *testing.T) {
		f := fenceFake(always(gone))
		tr := New(testConfig(), f, fenceOptions()).Transport(fenceBox(fenceName, ""), boxcore.TransportOptions{})
		for range 2 {
			code, err := tr.Exec(ctx, "echo demo", nil, nil, nil)
			requireKind(t, err, boxcore.KindTransport)
			if code != -1 || strings.Contains(err.Error(), fenceName) {
				t.Fatalf("exec on a gone machine = %d, %v", code, err)
			}
		}
		// Not remembered: the machine is read again on the next command.
		requireVerbs(t, f, "describe", "describe")
	})
	for _, bad := range []struct {
		name   string
		result boxexec.Result
		kind   boxcore.ErrorKind
	}{
		{"permission", boxexec.Result{Code: 1, Stderr: []byte("PERMISSION_DENIED")}, boxcore.KindDenied},
		{"garbage", boxexec.Result{Stdout: []byte("{")}, boxcore.KindOther},
		{"no-name", boxexec.Result{Stdout: []byte("{}")}, boxcore.KindOther},
		// "Not found" about anything but this machine is a failed read, not a machine that is gone.
		{"crash", boxexec.Result{Code: 1, Stderr: []byte("ModuleNotFoundError: No module named 'x' was not found")}, boxcore.KindOther},
		{"other-name", boxexec.Result{Code: 1, Stderr: []byte(goneText("demo-zone-a", fenceName+"-2"))}, boxcore.KindOther},
	} {
		for _, a := range fenceActions() {
			t.Run(bad.name+"-"+a.name, func(t *testing.T) {
				f := fenceFake(always(bad.result))
				got := a.run(t, New(testConfig(), f, fenceOptions()), fenceBox(fenceName, ""))
				for _, g := range got {
					requireKind(t, g.err, bad.kind)
					if e, ok := g.err.(*boxcore.Error); !ok || e.Op != a.op || g.n != a.refused {
						t.Fatalf("failed read returned %d, %v; want %d from %s", g.n, g.err, a.refused, a.op)
					}
				}
				// One read per command, and nothing acted on the machine.
				requireVerbs(t, f, slices.Repeat([]string{"describe"}, len(got))...)
			})
		}
	}
	t.Run("retry", func(t *testing.T) {
		// A failed read is not a verdict: the readiness poll retries, and the next command reads again.
		f := fenceFake(func(n int) (boxexec.Result, error) {
			if n == 0 {
				return boxexec.Result{Stdout: []byte("{")}, nil
			}
			return boxexec.Result{Stdout: row}, nil
		})
		tr := New(testConfig(), f, fenceOptions()).Transport(fenceBox(fenceName, ""), boxcore.TransportOptions{})
		code, err := tr.Exec(ctx, "echo demo", nil, nil, nil)
		requireKind(t, err, boxcore.KindOther)
		if code != -1 {
			t.Fatalf("failed read returned %d", code)
		}
		if code, err = tr.Exec(ctx, "echo demo", nil, nil, nil); err != nil || code != 0 {
			t.Fatalf("retry = %d, %v", code, err)
		}
		requireVerbs(t, f, "describe", "describe", "ssh")
	})
}

// TestFenceFresh: a pass covers the commands of the next fenceFresh and no longer. A command sent later (the harvest after a
// long suite, a machine that was preempted and whose name was taken again) reads the live machine again before it goes out,
// and a refusal at that read is final.
func TestFenceFresh(t *testing.T) {
	ctx := context.Background()
	ours := instanceJSON(t, fenceName, "RUNNING", ourLabels(), "")
	changed := ourLabels()
	changed["managed-by"] = "other-tool"
	decoy := instanceJSON(t, fenceName, "RUNNING", changed, "")
	start := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	reads := func(f *boxexec.Fake) int { return strings.Count(strings.Join(verbs(f), " "), "describe") }
	t.Run("reads-again-after-expiry", func(t *testing.T) {
		now := start
		o := fenceOptions()
		o.Now = func() time.Time { return now }
		f := fenceFake(always(boxexec.Result{Stdout: ours}))
		tr := New(testConfig(), f, o).Transport(fenceBox(fenceName, ""), boxcore.TransportOptions{})
		for _, step := range []struct {
			offset time.Duration // since the first command
			reads  int           // reads of the machine so far, once this command has gone out
		}{
			{0, 1}, {fenceFresh - time.Second, 1}, {fenceFresh + time.Second, 2},
			{2*fenceFresh - time.Second, 2}, {2*fenceFresh + time.Second, 3},
		} {
			now = start.Add(step.offset)
			if code, err := tr.Exec(ctx, "echo demo", nil, nil, nil); err != nil || code != 0 {
				t.Fatalf("exec at +%s = %d, %v", step.offset, code, err)
			}
			if got := reads(f); got != step.reads {
				t.Fatalf("after the command at +%s the machine was read %d times, want %d", step.offset, got, step.reads)
			}
		}
	})
	t.Run("refuses-at-the-new-read", func(t *testing.T) {
		now := start
		o := fenceOptions()
		o.Now = func() time.Time { return now }
		f := fenceFake(func(n int) (boxexec.Result, error) {
			if n == 0 {
				return boxexec.Result{Stdout: ours}, nil
			}
			return boxexec.Result{Stdout: decoy}, nil
		})
		tr := New(testConfig(), f, o).Transport(fenceBox(fenceName, ""), boxcore.TransportOptions{})
		if code, err := tr.Exec(ctx, "echo demo", nil, nil, nil); err != nil || code != 0 {
			t.Fatalf("first exec = %d, %v", code, err)
		}
		now = start.Add(fenceFresh + time.Second)
		code, err := tr.Exec(ctx, "echo demo", nil, nil, nil)
		requireRefusal(t, err, "ssh", "label managed-by differs", []string{"other-tool"})
		if code != -1 {
			t.Fatalf("a refused command returned %d", code)
		}
		// The first command went out, the second was read and stopped: one ssh in all.
		requireVerbs(t, f, "describe", "ssh", "describe")
	})
}
