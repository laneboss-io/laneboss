package boxaws

import (
	"context"
	"encoding/base64"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

func TestLaunchArgv(t *testing.T) {
	for i, name := range []string{"mapped", "discovered", "arm"} {
		t.Run(name, func(t *testing.T) {
			cfg, options, req, c := demoConfig(), demoOptions(), demoRequest(), demoCandidate()
			cfg.Region += "-" + name
			cfg.AMI += "-" + name
			cfg.KeyName += "-" + name
			cfg.SecurityGroup += "-" + name
			cfg.VPC += "-" + name
			cfg.ProjectTag += "-" + name
			cfg.ArmAMISSM += "/" + name
			options.Org += "-" + name
			options.NamePrefix += name + "-"
			req.Owner += "-" + name
			req.Lane += "-" + name
			req.RunID += "-" + name
			c.Zone = "zone-demo-" + name
			req.RootGB += i
			req.Purpose += "-" + name
			guest := boxcore.Guest{Startup: "printf '%s\\n' " + name + "\nexit 0\n"}
			fake := demoFake(t)
			image, subnet := cfg.AMI, "subnet-demo-map"
			cfg.Subnets = map[string]string{c.Zone: subnet}
			if name == "discovered" {
				cfg.Subnets = nil
				subnet = "subnet-demo1"
			}
			if name == "arm" {
				c.Arch, c.Type = "arm64", "c7g.xlarge"
				image = "ami-demo-arm"
			}
			b, err := New(cfg, fake, options).Launch(context.Background(), req, c, guest)
			if err != nil {
				t.Fatal(err)
			}
			call := oneCall(t, fake, "aws", "ec2 run-instances")
			for flag, value := range map[string]string{
				"--image-id": image, "--instance-type": c.Type, "--key-name": cfg.KeyName,
				"--security-group-ids": cfg.SecurityGroup, "--subnet-id": subnet,
				"--instance-initiated-shutdown-behavior": "terminate",
				"--query":                                "Instances[0].InstanceId", "--output": "text",
			} {
				if flagValue(t, call.Args, flag) != value {
					t.Fatalf("wrong value for %s", flag)
				}
			}
			wantArgs(t, call.Args[:2], []string{"ec2", "run-instances"})
			wantArgs(t, flagValues(t, call.Args, "--associate-public-ip-address"), []string{})
			market := flagValue(t, call.Args, "--instance-market-options")
			if market != "MarketType=spot,SpotOptions={SpotInstanceType=one-time,"+
				"InstanceInterruptionBehavior=terminate}" {
				t.Fatal("spot market or interruption policy differs")
			}
			mapping := "DeviceName=/dev/sda1,Ebs={VolumeSize=" + strconv.Itoa(req.RootGB) +
				",VolumeType=gp3,DeleteOnTermination=true}"
			if flagValue(t, call.Args, "--block-device-mappings") != mapping {
				t.Fatal("root volume mapping differs")
			}
			encoded := flagValue(t, call.Args, "--user-data")
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil || string(decoded) != guest.Startup || strings.ContainsAny(encoded, "\r\n") {
				t.Fatal("user data is not the exact single-line base64 guest text")
			}
			labels := map[string]string{
				"Project": cfg.ProjectTag, "Name": options.NamePrefix + req.Purpose, "Owner": req.Owner,
				"Lane": req.Lane, "Purpose": req.Purpose, "Org": options.Org, "RunId": req.RunID,
				"ManagedBy": "laneboss",
			}
			specs := flagValues(t, call.Args, "--tag-specifications")
			if len(specs) != 2 {
				t.Fatalf("wanted two tag arguments, got %d", len(specs))
			}
			checkTagSpec(t, specs[0], "instance", labels)
			checkTagSpec(t, specs[1], "volume", labels)
			if b.Provider != "aws" || b.ID != "i-demo1" || b.Name != labels["Name"] ||
				b.Type != c.Type || b.Zone != c.Zone || b.Region != cfg.Region ||
				b.Project != cfg.ProjectTag || b.QuoteUSDHour != 0 || !reflect.DeepEqual(b.Labels, labels) {
				t.Fatalf("wrong launch facts: %+v", b)
			}
			if name == "discovered" {
				lookup := oneCall(t, fake, "aws", "ec2 describe-subnets")
				wantArgs(t, lookup.Args, []string{"ec2", "describe-subnets", "--filters",
					"Name=vpc-id,Values=" + cfg.VPC, "Name=availability-zone,Values=" + c.Zone,
					"Name=map-public-ip-on-launch,Values=true", "--query", "Subnets[0].SubnetId", "--output", "text"})
			} else if len(fake.CallsMatching("aws", "describe-subnets")) != 0 {
				t.Fatal("mapped subnet still queried AWS")
			}
			if name == "arm" {
				lookup := oneCall(t, fake, "aws", "ssm get-parameter")
				wantArgs(t, lookup.Args, []string{"ssm", "get-parameter", "--name", cfg.ArmAMISSM,
					"--query", "Parameter.Value", "--output", "text"})
			} else if len(fake.CallsMatching("aws", "get-parameter")) != 0 {
				t.Fatal("x86 image still queried SSM")
			}
		})
	}
}

func checkTagSpec(t *testing.T, spec, resource string, want map[string]string) {
	t.Helper()
	prefix := "ResourceType=" + resource + ",Tags=["
	if !strings.HasPrefix(spec, prefix) || !strings.HasSuffix(spec, "]") {
		t.Fatalf("wrong %s tag specification", resource)
	}
	body := strings.TrimSuffix(strings.TrimPrefix(spec, prefix), "]")
	got := make(map[string]string)
	for _, entry := range strings.Split(body, "},{") {
		entry = strings.TrimSuffix(strings.TrimPrefix(entry, "{"), "}")
		key, value, ok := strings.Cut(entry, ",Value=")
		if !ok || !strings.HasPrefix(key, "Key=") {
			t.Fatal("invalid tag shorthand")
		}
		key = strings.TrimPrefix(key, "Key=")
		if _, duplicate := got[key]; duplicate {
			t.Fatal("duplicate tag key")
		}
		got[key] = value
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("wrong %s tags: got %v, want %v", resource, got, want)
	}
}

func TestLaunchValidation(t *testing.T) {
	bad := "unsafe,tag-value"
	cases := []struct {
		name, tag string
		change    func(*boxcore.AWSConfig, *Options, *boxcore.Request, *boxcore.Guest)
	}{
		{"project", "Project", func(c *boxcore.AWSConfig, o *Options, r *boxcore.Request, g *boxcore.Guest) { c.ProjectTag = bad }},
		{"name", "Name", func(c *boxcore.AWSConfig, o *Options, r *boxcore.Request, g *boxcore.Guest) { o.NamePrefix = bad }},
		{"owner", "Owner", func(c *boxcore.AWSConfig, o *Options, r *boxcore.Request, g *boxcore.Guest) { r.Owner = bad }},
		{"lane", "Lane", func(c *boxcore.AWSConfig, o *Options, r *boxcore.Request, g *boxcore.Guest) { r.Lane = bad }},
		{"purpose", "Purpose", func(c *boxcore.AWSConfig, o *Options, r *boxcore.Request, g *boxcore.Guest) { r.Purpose = "" }},
		{"org", "Org", func(c *boxcore.AWSConfig, o *Options, r *boxcore.Request, g *boxcore.Guest) { o.Org = bad }},
		{"run", "RunId", func(c *boxcore.AWSConfig, o *Options, r *boxcore.Request, g *boxcore.Guest) { r.RunID = bad }},
		{"root", "root size", func(c *boxcore.AWSConfig, o *Options, r *boxcore.Request, g *boxcore.Guest) { r.RootGB = 0 }},
		{"bytes", "startup", func(c *boxcore.AWSConfig, o *Options, r *boxcore.Request, g *boxcore.Guest) {
			g.Startup = strings.Repeat("é", 6001)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, options, req := demoConfig(), demoOptions(), demoRequest()
			guest := boxcore.Guest{Startup: "demo\n"}
			tc.change(&cfg, &options, &req, &guest)
			fake := demoFake(t)
			c := demoCandidate()
			c.Arch = "arm64"
			_, err := New(cfg, fake, options).Launch(context.Background(), req, c, guest)
			wantKind(t, err, boxcore.KindOther)
			if !strings.Contains(err.Error(), tc.tag) || strings.Contains(err.Error(), bad) || len(fake.Calls) != 0 {
				t.Fatal("validation did not stop safely before child processes")
			}
		})
	}
	t.Run("limit", func(t *testing.T) {
		fake := demoFake(t)
		guest := boxcore.Guest{Startup: strings.Repeat("é", 6000)}
		_, err := New(demoConfig(), fake, demoOptions()).Launch(context.Background(), demoRequest(), demoCandidate(), guest)
		if err != nil {
			t.Fatal(err)
		}
		call := oneCall(t, fake, "aws", "run-instances")
		data, err := base64.StdEncoding.DecodeString(flagValue(t, call.Args, "--user-data"))
		if err != nil || string(data) != guest.Startup || len(data) != 12000 {
			t.Fatal("valid user data at the byte limit differs")
		}
	})
}

func TestLaunchLookupsFail(t *testing.T) {
	for _, lookup := range []string{"subnet", "image"} {
		for _, output := range []string{"", "None\n"} {
			t.Run(lookup+"-"+strconv.Itoa(len(output)), func(t *testing.T) {
				cfg, c := demoConfig(), demoCandidate()
				needle := "ec2 describe-subnets"
				kind := boxcore.KindCapacity
				if lookup == "image" {
					c.Arch, needle, kind = "arm64", "ssm get-parameter", boxcore.KindOther
				}
				fake := &boxexec.Fake{Handlers: []boxexec.Handler{reply("aws", needle, output)}}
				_, err := New(cfg, fake, demoOptions()).Launch(context.Background(), demoRequest(), c, boxcore.Guest{})
				wantKind(t, err, kind)
				if len(fake.Calls) != 1 || len(fake.CallsMatching("aws", "run-instances")) != 0 {
					t.Fatal("failed lookup still launched or continued")
				}
				if lookup == "subnet" && !strings.Contains(err.Error(), "no public subnet") {
					t.Fatal("missing public subnet detail")
				}
			})
		}
	}
}

func TestLaunchRefusals(t *testing.T) {
	for _, tc := range []struct {
		code string
		kind boxcore.ErrorKind
	}{
		{"InsufficientInstanceCapacity", boxcore.KindCapacity},
		{"VcpuLimitExceeded", boxcore.KindQuota},
		{"UnauthorizedOperation", boxcore.KindDenied},
	} {
		t.Run(tc.code, func(t *testing.T) {
			cfg, c, options := demoConfig(), demoCandidate(), demoOptions()
			cfg.Subnets = map[string]string{c.Zone: "subnet-demo1"}
			sleeps := 0
			options.Sleep = func(context.Context, time.Duration) error {
				sleeps++
				return nil
			}
			fake := &boxexec.Fake{Handlers: []boxexec.Handler{{Name: "aws", ArgsContain: []string{"run-instances"},
				Respond: func(cmd boxexec.Cmd, n int) (boxexec.Result, error) {
					if n > 0 {
						return boxexec.Result{Stdout: []byte("i-demo1")}, nil
					}
					return boxexec.Result{Code: 255, Stderr: []byte(awsFailure(tc.code, "refused"))}, nil
				}}}}
			_, err := New(cfg, fake, options).Launch(context.Background(), demoRequest(), c, boxcore.Guest{})
			failure := wantKind(t, err, tc.kind)
			if failure.Code != tc.code || len(fake.Calls) != 1 || sleeps != 0 {
				t.Fatal("refusal was retried or classified incorrectly")
			}
		})
	}
}

func TestDryRun(t *testing.T) {
	for _, code := range []string{"DryRunOperation", "UnauthorizedOperation", "AuthFailure", "AccessDenied",
		"AccessDeniedException", "InvalidClientTokenId", "ExpiredToken", "success", "OtherFailure"} {
		t.Run(code, func(t *testing.T) {
			fake := demoFake(t)
			cfg, req, c := demoConfig(), demoRequest(), demoCandidate()
			cfg.Subnets = map[string]string{c.Zone: "subnet-demo1"}
			guest := boxcore.Guest{Startup: "demo-startup\n"}
			p := New(cfg, fake, demoOptions())
			if _, err := p.Launch(context.Background(), req, c, guest); err != nil {
				t.Fatal(err)
			}
			launch := oneCall(t, fake, "aws", "run-instances")
			fake.Handlers = []boxexec.Handler{{Name: "aws", ArgsContain: []string{"run-instances"},
				Respond: func(boxexec.Cmd, int) (boxexec.Result, error) {
					if code == "success" {
						return boxexec.Result{Stdout: []byte("i-demo1")}, nil
					}
					return boxexec.Result{Code: 255, Stderr: []byte(awsFailure(code, "answer"))}, nil
				}}}
			answer, err := p.DryRun(context.Background(), req, c, guest)
			calls := fake.CallsMatching("aws", "run-instances")
			if len(calls) != 2 {
				t.Fatalf("wanted launch and dry-run calls, got %d", len(calls))
			}
			wantArgs(t, calls[1].Args, append(launch.Args, "--dry-run"))
			switch code {
			case "success", "OtherFailure":
				wantKind(t, err, boxcore.KindOther)
			default:
				if err != nil || answer.Allowed != (code == "DryRunOperation") || answer.Code != code {
					t.Fatalf("wrong dry-run answer: %+v, %v", answer, err)
				}
			}
		})
	}
}
