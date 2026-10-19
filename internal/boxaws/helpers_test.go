package boxaws

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

func demoConfig() boxcore.AWSConfig {
	return boxcore.AWSConfig{
		Profile: "demo-profile", Region: "region-demo", ProjectTag: "project-demo",
		VPC: "vpc-demo1", SecurityGroup: "sg-demo1", AMI: "ami-demo-x86",
		ArmAMISSM: "/aws/service/ami-demo/" + "arm64/image-id", KeyName: "key-demo",
		SSHUser: "user-demo", SSHIdentity: "/tmp/lb-sp-aws-demo-key",
		FamiliesX86: []string{"c7i", "m7i"}, FamiliesArm: []string{"c7g", "r7g"},
	}
}

func demoOptions() Options {
	return Options{
		Org: "example-org", NamePrefix: "lb-demo-",
		Getenv: func(string) string { return "" },
		Now: func() time.Time {
			return time.Date(2026, 10, 1, 13, 2, 3, 0, time.FixedZone("demo", 8*3600))
		},
		Sleep: func(context.Context, time.Duration) error {
			return errors.New("unexpected sleep")
		},
	}
}

func demoRequest() boxcore.Request {
	return boxcore.Request{Purpose: "load-demo", Lane: "demo-lane", Owner: "owner-demo",
		RunID: "run-demo1", VCPU: 4, Arch: "any", RootGB: 37}
}

func demoCandidate() boxcore.Candidate {
	return boxcore.Candidate{Type: "c7i.xlarge", Zone: "zone-demo-a", Region: "region-demo",
		Arch: "x86", PriceUSDHour: 0.19}
}

func reply(name, needle, stdout string) boxexec.Handler {
	return boxexec.Handler{Name: name, ArgsContain: []string{needle},
		Respond: func(boxexec.Cmd, int) (boxexec.Result, error) {
			return boxexec.Result{Stdout: []byte(stdout)}, nil
		}}
}

func awsFailure(code, message string) string {
	return "An error occurred (" + code + ") when calling the RunInstances operation: " + message
}

func demoInfo() map[string]any {
	return map[string]any{
		"InstanceId": "i-demo1", "InstanceType": "m7i.xlarge", "ImageId": "ami-demo1",
		"LaunchTime": "2026-10-01T05:02:03.123Z", "PublicIpAddress": "127.0.0.1",
		"SpotInstanceRequestId": "sir-demo1", "Placement": map[string]any{"AvailabilityZone": "zone-demo-b"},
		"State": map[string]any{"Name": "running"},
		"Tags": []map[string]string{
			{"Key": "Name", "Value": "lb-demo-load-demo"}, {"Key": "Project", "Value": "project-demo"},
			{"Key": "ManagedBy", "Value": "laneboss"}, {"Key": "Org", "Value": "example-org"},
		},
	}
}

func jsonText(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func instanceText(t *testing.T, infos ...map[string]any) string {
	t.Helper()
	return jsonText(t, map[string]any{
		"Reservations": []map[string]any{{"Instances": infos}},
	})
}

func demoFake(t *testing.T) *boxexec.Fake {
	t.Helper()
	return &boxexec.Fake{Handlers: []boxexec.Handler{
		reply("aws", "sts get-caller-identity", `{"UserId":"identity-demo"}`),
		reply("aws", "ec2 describe-spot-price-history", `{"SpotPriceHistory":[`+
			`{"InstanceType":"c7i.xlarge","AvailabilityZone":"zone-demo-a",`+
			`"SpotPrice":"0.11","Timestamp":"2026-10-01T05:02:03Z"}]}`),
		reply("aws", "ssm get-parameter", "ami-demo-arm\n"),
		reply("aws", "ec2 describe-subnets", "subnet-demo1\n"),
		{Name: "aws", ArgsContain: []string{"ec2 run-instances"},
			Respond: func(c boxexec.Cmd, n int) (boxexec.Result, error) {
				for _, arg := range c.Args {
					if arg == "--dry-run" {
						return boxexec.Result{Code: 255, Stderr: []byte(awsFailure("DryRunOperation", "permitted"))}, nil
					}
				}
				return boxexec.Result{Stdout: []byte("i-demo1\n")}, nil
			}},
		reply("aws", "ec2 wait instance-running", "{}"),
		reply("aws", "ec2 describe-instances", instanceText(t, demoInfo())),
		reply("aws", "ec2 describe-security-groups", `{"SecurityGroups":[{"IpPermissions":[]}]}`),
		reply("aws", "ec2 authorize-security-group-ingress", "{}"),
		reply("aws", "ec2 terminate-instances", "{}"),
		reply("curl", "-fsS", "127.0.0.1\n"),
		reply("ssh", "BatchMode=yes", "output-demo"),
	}}
}

func oneCall(t *testing.T, fake *boxexec.Fake, name string, contains ...string) boxexec.Call {
	t.Helper()
	calls := fake.CallsMatching(name, contains...)
	if len(calls) != 1 {
		t.Fatalf("wanted one %s call matching %v, got %d", name, contains, len(calls))
	}
	return calls[0]
}

func flagValues(t *testing.T, args []string, flag string) []string {
	t.Helper()
	index := -1
	for i, arg := range args {
		if arg == flag {
			if index != -1 {
				t.Fatalf("duplicate flag %s", flag)
			}
			index = i
		}
	}
	if index == -1 {
		t.Fatalf("missing flag %s", flag)
	}
	end := index + 1
	for end < len(args) && !strings.HasPrefix(args[end], "--") {
		end++
	}
	return args[index+1 : end]
}

func flagValue(t *testing.T, args []string, flag string) string {
	t.Helper()
	values := flagValues(t, args, flag)
	if len(values) != 1 {
		t.Fatalf("flag %s wanted one value, got %d", flag, len(values))
	}
	return values[0]
}

func wantArgs(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("arguments differ:\ngot  %q\nwant %q", got, want)
	}
}

func wantKind(t *testing.T, err error, kind boxcore.ErrorKind) *boxcore.Error {
	t.Helper()
	var failure *boxcore.Error
	if !errors.As(err, &failure) || failure.Kind != kind {
		t.Fatalf("wanted *boxcore.Error of kind %s, got %v", kind, err)
	}
	return failure
}
