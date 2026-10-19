package boxgcp

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

// TestDescribe rejects wrong state maps, missing reasons and lost not-found answers.
func TestDescribe(t *testing.T) {
	for _, tc := range []struct{ status, state string }{
		{"PROVISIONING", boxcore.StatePending}, {"STAGING", boxcore.StatePending}, {"REPAIRING", boxcore.StatePending},
		{"RUNNING", boxcore.StateRunning}, {"STOPPING", boxcore.StateStopping}, {"SUSPENDING", boxcore.StateStopping},
		{"TERMINATED", boxcore.StateStopped}, {"SUSPENDED", boxcore.StateStopped}, {"STOPPED", boxcore.StateStopped},
		{"DEMO_UNKNOWN", boxcore.StateUnknown},
	} {
		t.Run(tc.status, func(t *testing.T) {
			f := resultFake(boxexec.Result{Stdout: instanceJSON(t, "lb-box-1", tc.status, nil, "")}, nil)
			got, err := New(testConfig(), f, testOptions()).Describe(context.Background(), testBox())
			want := boxcore.State{Name: tc.state, Raw: tc.status, Reason: "demo reason"}
			if err != nil || got != want {
				t.Fatal("state, raw status or statusMessage was lost")
			}
			requireArgs(t, onlyCall(t, f).Args, []string{
				"compute", "instances", "describe", "lb-box-1", "--zone=demo-zone-a",
				"--format=json", "--project=demo-project", "--quiet",
			})
		})
	}
	// A machine is gone only when the answer names it, the way gcloud words it.
	named := goneText("demo-zone-a", "lb-box-1")
	for _, tc := range []struct{ name, text string }{
		{"plain", named}, {"http", "HTTPError 404: " + named}, {"reason", named + " notFound"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := resultFake(boxexec.Result{Code: 1, Stderr: []byte(tc.text)}, nil)
			got, err := New(testConfig(), f, testOptions()).Describe(context.Background(), testBox())
			if err != nil || got != (boxcore.State{Name: boxcore.StateGone}) {
				t.Fatal("missing instance was not gone")
			}
			onlyCall(t, f)
		})
	}
	t.Run("denied", func(t *testing.T) {
		f := resultFake(boxexec.Result{Code: 1, Stderr: []byte("PERMISSION_DENIED")}, nil)
		_, err := New(testConfig(), f, testOptions()).Describe(context.Background(), testBox())
		requireKind(t, err, boxcore.KindDenied)
		onlyCall(t, f)
	})
}

// TestDescribeNotAnAnswer rejects taking a failed read for a machine that is gone: an answer that says "not found" about
// something else (a crashed gcloud, a zone, another machine whose name starts with ours) leaves the state unknown, and a
// teardown on it must neither succeed nor delete.
func TestDescribeNotAnAnswer(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"crash", "Traceback (most recent call last):\nModuleNotFoundError: No module named 'googlecloudsdk' was not found"},
		{"zone", "The resource 'projects/demo-project" + "/zones/demo-zone-a' was not found"},
		{"longer-name", goneText("demo-zone-a", "lb-box-10")},
		{"bare-404", "HTTPError 404"},
		{"other-instance", goneText("demo-zone-a", "other-box")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := resultFake(boxexec.Result{Code: 1, Stderr: []byte(tc.text)}, nil)
			p := New(testConfig(), f, testOptions())
			got, err := p.Describe(context.Background(), testBox())
			requireKind(t, err, boxcore.KindOther)
			if got == (boxcore.State{Name: boxcore.StateGone}) {
				t.Fatal("a failed read was taken for a machine that is gone")
			}
			if err := p.Teardown(context.Background(), testBox()); err == nil {
				t.Fatal("teardown reported success on a machine it could not read")
			}
			for _, call := range f.Calls {
				if strings.Contains(strings.Join(call.Args, " "), "delete") {
					t.Fatal("teardown deleted a machine it could not read")
				}
			}
		})
	}
}

// TestTeardown rejects bypassed live ownership gates and deletes without disks.
func TestTeardown(t *testing.T) {
	cases := []struct {
		name, instanceName, prefix, managed, org string
		notFound, deleteFail                     bool
		calls                                    int
		kind                                     boxcore.ErrorKind
	}{
		{"wrong-prefix", "other-box-1", "LB-", "laneboss", "example-org", false, false, 1, boxcore.KindDenied},
		{"missing-managed", "lb-box-1", "LB-", "", "example-org", false, false, 1, boxcore.KindDenied},
		{"missing-org", "lb-box-1", "LB-", "laneboss", "", false, false, 1, boxcore.KindDenied},
		{"wrong-managed", "lb-box-1", "LB-", "other", "example-org", false, false, 1, boxcore.KindDenied},
		{"wrong-org", "lb-box-1", "LB-", "laneboss", "other-org", false, false, 1, boxcore.KindDenied},
		{"empty-prefix", "lb-box-1", "", "laneboss", "example-org", false, false, 1, boxcore.KindDenied},
		{"owned", "lb-box-1", "LB-", "laneboss", "example-org", false, false, 2, boxcore.KindOther},
		{"gone", "lb-box-1", "LB-", "", "", true, false, 1, boxcore.KindOther},
		{"delete-error", "lb-box-1", "LB-", "laneboss", "example-org", false, true, 2, boxcore.KindQuota},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Every row carries the labels the fence needs besides the two it varies, so a refusal can come
			// only from the row's own defect.
			labels := map[string]string{"lb-owner": "demo-owner", "lb-lane": "demo-lane", "lb-run": "demo-run"}
			if tc.managed != "" {
				labels["managed-by"] = tc.managed
			}
			if tc.org != "" {
				labels["lb-org"] = tc.org
			}
			row := instanceJSON(t, tc.instanceName, "RUNNING", labels, "")
			f := &boxexec.Fake{Handlers: []boxexec.Handler{
				{Name: "gcloud", ArgsContain: []string{"instances describe"}, Respond: func(boxexec.Cmd, int) (boxexec.Result, error) {
					if tc.notFound {
						return boxexec.Result{Code: 1, Stderr: []byte(goneText("demo-zone-a", tc.instanceName))}, nil
					}
					return boxexec.Result{Stdout: row}, nil
				}},
				{Name: "gcloud", ArgsContain: []string{"instances delete"}, Respond: func(boxexec.Cmd, int) (boxexec.Result, error) {
					if tc.deleteFail {
						return boxexec.Result{Code: 1, Stderr: []byte("QUOTA_EXCEEDED")}, nil
					}
					return boxexec.Result{}, nil
				}},
			}}
			b, o := testBox(), testOptions()
			b.ID, b.Name, o.NamePrefix = tc.instanceName, tc.instanceName, tc.prefix
			b.Labels = map[string]string{"managed-by": "laneboss", "lb-org": "example-org"}
			err := New(testConfig(), f, o).Teardown(context.Background(), b)
			if tc.kind != boxcore.KindOther {
				requireKind(t, err, tc.kind)
			} else if err != nil {
				t.Fatal(err)
			}
			if len(f.Calls) != tc.calls {
				t.Fatal("ownership refusal deleted a box or matching box was not deleted")
			}
			requireArgs(t, f.Calls[0].Args, []string{
				"compute", "instances", "describe", tc.instanceName, "--zone=demo-zone-a",
				"--format=json", "--project=demo-project", "--quiet",
			})
			if tc.calls == 2 {
				requireArgs(t, f.Calls[1].Args, []string{
					"compute", "instances", "delete", tc.instanceName, "--zone=demo-zone-a",
					"--delete-disks=all", "--project=demo-project", "--quiet",
				})
			}
		})
	}
}

// TestList rejects wrong filters, path parsing, labels and timestamp offsets.
func TestList(t *testing.T) {
	for _, org := range []string{"", "Example.Org"} {
		t.Run(org, func(t *testing.T) {
			labels := map[string]string{"managed-by": "laneboss", "lb-org": "example-org", "lb-run": "run-1"}
			first := instanceJSON(t, "lb-box-1", "RUNNING", labels, "127.0.0.1")
			second := instanceJSON(t, "lb-box-2", "TERMINATED", labels, "")
			data := []byte("[" + string(first) + "," + string(second) + "]")
			f := resultFake(boxexec.Result{Stdout: data}, nil)
			got, err := New(testConfig(), f, testOptions()).List(context.Background(), boxcore.ListFilter{Org: org})
			if err != nil || len(got) != 2 {
				t.Fatal("list lost instances")
			}
			for index, name := range []string{"lb-box-1", "lb-box-2"} {
				b := got[index]
				address := ""
				if index == 0 {
					address = "127.0.0.1"
				}
				if b.Provider != "gcp" || b.Name != name || b.ID != name || b.Type != "demo-small" ||
					b.Zone != "demo-zone-a" || b.Region != "demo-region" || b.Project != "demo-project" ||
					b.Address != address || b.LaunchTimeUTC != "2026-10-14T12:46:15Z" || !reflect.DeepEqual(b.Labels, labels) {
					t.Fatal("list did not parse the reported fields")
				}
			}
			filter := "--filter=labels.managed-by=laneboss"
			if org != "" {
				filter += " AND labels.lb-org=example-org"
			}
			requireArgs(t, onlyCall(t, f).Args, []string{
				"compute", "instances", "list", filter, "--format=json", "--project=demo-project", "--quiet",
			})
		})
	}
}
