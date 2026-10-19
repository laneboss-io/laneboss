package boxaws

import (
	"context"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

func TestDescribeGone(t *testing.T) {
	for _, tc := range []struct {
		code string
		kind boxcore.ErrorKind
	}{
		{"InvalidInstanceID.NotFound", boxcore.KindNotFound},
		{"InvalidSpotInstanceRequestID.NotFound", boxcore.KindNotFound},
		{"AccessDenied", boxcore.KindDenied},
	} {
		t.Run(tc.code, func(t *testing.T) {
			fake := &boxexec.Fake{Handlers: []boxexec.Handler{{Name: "aws", ArgsContain: []string{"describe-instances"},
				Respond: func(boxexec.Cmd, int) (boxexec.Result, error) {
					return boxexec.Result{Code: 255, Stderr: []byte(awsFailure(tc.code, "missing"))}, nil
				}}}}
			got, err := New(demoConfig(), fake, demoOptions()).Describe(context.Background(), boxcore.Box{ID: "i-demo1"})
			if tc.code == "InvalidInstanceID.NotFound" {
				if err != nil || got.Name != boxcore.StateGone {
					t.Fatal("missing instance did not become gone")
				}
			} else {
				wantKind(t, err, tc.kind)
			}
			if len(fake.Calls) != 1 {
				t.Fatal("describe refusal was retried")
			}
		})
	}
}

func TestDescribeEmpty(t *testing.T) {
	fake := &boxexec.Fake{Handlers: []boxexec.Handler{reply("aws", "describe-instances", `{"Reservations": []}`)}}
	got, err := New(demoConfig(), fake, demoOptions()).Describe(context.Background(), boxcore.Box{ID: "i-demo1"})
	if err != nil || got.Name != boxcore.StateGone {
		t.Fatal("an empty answer for the id did not become gone")
	}
}

func TestDescribeReason(t *testing.T) {
	code, message := "Server.SpotInstanceTermination", "capacity was reclaimed"
	transition := "provider action (2026-10-01 05:06:07 UTC)"
	for _, state := range []string{"stopped", "terminated", "running", "shutting-down"} {
		t.Run(state, func(t *testing.T) {
			info := demoInfo()
			info["State"] = map[string]string{"Name": state}
			info["StateReason"] = map[string]string{"Code": code, "Message": message}
			info["StateTransitionReason"] = transition
			fake := &boxexec.Fake{Handlers: []boxexec.Handler{reply("aws", "describe-instances", instanceText(t, info))}}
			got, err := New(demoConfig(), fake, demoOptions()).Describe(context.Background(), boxcore.Box{ID: "i-demo1"})
			if err != nil || got.Reason != code+"; "+message+"; "+transition {
				t.Fatalf("interruption reason differs: %+v, %v", got, err)
			}
			wantTime := ""
			if state == "stopped" || state == "terminated" {
				wantTime = "2026-10-01T05:06:07Z"
			}
			if got.TransitionUTC != wantTime {
				t.Fatal("transition timestamp or state gate differs")
			}
		})
	}
	t.Run("sparse", func(t *testing.T) {
		info := demoInfo()
		info["State"] = map[string]string{"Name": "terminated"}
		info["StateReason"] = map[string]string{"Message": message}
		info["StateTransitionReason"] = "invalid timestamp"
		fake := &boxexec.Fake{Handlers: []boxexec.Handler{reply("aws", "describe-instances", instanceText(t, info))}}
		got, err := New(demoConfig(), fake, demoOptions()).Describe(context.Background(), boxcore.Box{ID: "i-demo1"})
		if err != nil || got.Reason != message+"; invalid timestamp" || got.TransitionUTC != "" {
			t.Fatal("missing reason parts or invalid time were mishandled")
		}
	})
}

func TestWaitFailures(t *testing.T) {
	for _, phase := range []string{"wait", "address", "json", "empty", "time"} {
		t.Run(phase, func(t *testing.T) {
			info := demoInfo()
			if phase == "address" {
				delete(info, "PublicIpAddress")
			}
			if phase == "time" {
				info["LaunchTime"] = "invalid time"
			}
			text := instanceText(t, info)
			kind, count := boxcore.KindOther, 2
			if phase == "json" {
				text = "{"
			}
			if phase == "empty" {
				text, kind = `{"Reservations":[]}`, boxcore.KindNotFound
			}
			fake := &boxexec.Fake{Handlers: []boxexec.Handler{
				reply("aws", "ec2 wait instance-running", "{}"), reply("aws", "describe-instances", text),
			}}
			if phase == "wait" {
				kind, count = boxcore.KindDenied, 1
				fake.Handlers[0].Respond = func(boxexec.Cmd, int) (boxexec.Result, error) {
					return boxexec.Result{Code: 255, Stderr: []byte(awsFailure("AccessDenied", "refused"))}, nil
				}
			}
			_, err := New(demoConfig(), fake, demoOptions()).WaitRunning(context.Background(), boxcore.Box{ID: "i-demo1"})
			wantKind(t, err, kind)
			if len(fake.Calls) != count {
				t.Fatal("wait failure was swallowed or retried")
			}
		})
	}
}

func TestList(t *testing.T) {
	for _, org := range []string{"example-org", ""} {
		t.Run("org-"+org, func(t *testing.T) {
			first, second := demoInfo(), demoInfo()
			second["InstanceId"] = "i-demo2"
			second["Tags"] = []map[string]string{{"Key": "Name", "Value": "lb-demo-other"},
				{"Key": "Project", "Value": "project-other"}, {"Key": "Purpose", "Value": "other-demo"}}
			text := jsonText(t, map[string]any{"Reservations": []map[string]any{
				{"Instances": []map[string]any{first}}, {"Instances": []map[string]any{second}},
			}})
			fake := &boxexec.Fake{Handlers: []boxexec.Handler{reply("aws", "describe-instances", text)}}
			got, err := New(demoConfig(), fake, demoOptions()).List(context.Background(), boxcore.ListFilter{Org: org})
			if err != nil || len(got) != 2 || got[0].ID != "i-demo1" || got[1].ID != "i-demo2" ||
				got[0].Labels["ManagedBy"] != "laneboss" || got[1].Labels["Purpose"] != "other-demo" ||
				got[1].Name != "lb-demo-other" || got[1].Project != "project-other" {
				t.Fatalf("list did not read every reservation and tag: %+v, %v", got, err)
			}
			call := oneCall(t, fake, "aws", "describe-instances")
			want := []string{"ec2", "describe-instances", "--filters", "Name=tag:ManagedBy,Values=laneboss"}
			if org != "" {
				want = append(want, "Name=tag:Org,Values="+org)
			}
			want = append(want, "Name=instance-state-name,Values=pending,running,stopping,stopped", "--output", "json")
			wantArgs(t, call.Args, want)
		})
	}
	t.Run("empty", func(t *testing.T) {
		fake := &boxexec.Fake{Handlers: []boxexec.Handler{reply("aws", "describe-instances", `{"Reservations":[]}`)}}
		got, err := New(demoConfig(), fake, demoOptions()).List(context.Background(), boxcore.ListFilter{})
		if err != nil || len(got) != 0 || len(fake.Calls) != 1 {
			t.Fatal("empty list became an error or extra call")
		}
	})
}

func TestTeardown(t *testing.T) {
	for _, gate := range []string{"disabled", "name", "contains", "managed", "org", "missing-name",
		"missing-managed", "missing-org", "empty-prefix", "empty-org", "matches"} {
		t.Run(gate, func(t *testing.T) {
			cfg, options := demoConfig(), demoOptions()
			cfg.AllowTerminate = gate != "disabled"
			labels := map[string]string{"Name": options.NamePrefix + "load-demo", "ManagedBy": "laneboss", "Org": options.Org}
			switch gate {
			case "name":
				labels["Name"] = "other-name"
			case "contains":
				labels["Name"] = "other-" + options.NamePrefix + "load-demo"
			case "managed":
				labels["ManagedBy"] = "other-manager"
			case "org":
				labels["Org"] = "other-org"
			case "missing-name":
				delete(labels, "Name")
			case "missing-managed":
				delete(labels, "ManagedBy")
			case "missing-org":
				delete(labels, "Org")
			case "empty-prefix":
				options.NamePrefix = ""
			case "empty-org":
				options.Org = ""
				labels["Org"] = ""
			}
			var tags []map[string]string
			for _, key := range []string{"Name", "ManagedBy", "Org"} {
				if value, present := labels[key]; present {
					tags = append(tags, map[string]string{"Key": key, "Value": value})
				}
			}
			info := demoInfo()
			if gate == "matches" {
				info["InstanceId"] = "i-demo2"
			}
			info["Tags"] = tags
			fake := &boxexec.Fake{Handlers: []boxexec.Handler{
				reply("aws", "describe-instances", instanceText(t, info)), reply("aws", "terminate-instances", "{}"),
			}}
			b := boxcore.Box{ID: "i-demo1", Name: "lb-demo-load-demo", Labels: map[string]string{
				"Name": "lb-demo-load-demo", "ManagedBy": "laneboss", "Org": "example-org"}}
			if gate == "matches" {
				b.ID, b.Name, b.Labels = "i-demo2", "stale-name-demo", nil
			}
			err := New(cfg, fake, options).Teardown(context.Background(), b)
			if gate == "disabled" {
				wantKind(t, err, boxcore.KindUnsupported)
				if len(fake.Calls) != 0 {
					t.Fatal("disabled teardown made a call")
				}
			} else if gate == "matches" {
				if err != nil || len(fake.Calls) != 2 {
					t.Fatalf("owned box did not terminate: %v", err)
				}
				call := oneCall(t, fake, "aws", "terminate-instances")
				wantArgs(t, call.Args, []string{"ec2", "terminate-instances", "--instance-ids", b.ID, "--output", "json"})
			} else {
				wantKind(t, err, boxcore.KindDenied)
				if len(fake.Calls) != 1 || len(fake.CallsMatching("aws", "terminate-instances")) != 0 {
					t.Fatal("ownership mismatch reached termination")
				}
			}
			if cfg.AllowTerminate {
				call := oneCall(t, fake, "aws", "describe-instances")
				wantArgs(t, call.Args, []string{"ec2", "describe-instances", "--instance-ids", b.ID, "--output", "json"})
			}
		})
	}
	t.Run("terminate-failure", func(t *testing.T) {
		cfg := demoConfig()
		cfg.AllowTerminate = true
		fake := demoFake(t)
		fake.Handlers = append([]boxexec.Handler{{Name: "aws", ArgsContain: []string{"terminate-instances"},
			Respond: func(boxexec.Cmd, int) (boxexec.Result, error) {
				return boxexec.Result{Code: 255, Stderr: []byte(awsFailure("AccessDenied", "refused"))}, nil
			}}}, fake.Handlers...)
		err := New(cfg, fake, demoOptions()).Teardown(context.Background(), boxcore.Box{ID: "i-demo1"})
		wantKind(t, err, boxcore.KindDenied)
		if len(fake.Calls) != 2 || !strings.Contains(err.Error(), "refused") {
			t.Fatal("terminate failure was swallowed")
		}
	})
}
