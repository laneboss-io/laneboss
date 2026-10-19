package boxaws

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

func TestEnsureIngress(t *testing.T) {
	for _, tc := range []struct {
		name, protocol, cidr string
		from, to             int
		present              bool
	}{
		{"present", "tcp", "127.0.0.1/32", 22, 22, true},
		{"absent", "", "", 0, 0, false},
		{"protocol", "udp", "127.0.0.1/32", 22, 22, false},
		{"port", "tcp", "127.0.0.1/32", 443, 443, false},
		{"range", "tcp", "127.0.0.1/32", 22, 23, false},
		{"cidr", "tcp", "127.0.0.1/24", 22, 22, false},
		{"address", "", "", 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := demoConfig()
			ip := "127.0.0.1"
			if tc.name == "address" {
				ip = strings.Join([]string{"192", "0", "2", "7"}, ".")
			}
			url := "https://checkip." + "amazonaws.com"
			if tc.name == "absent" {
				cfg.MyAddressURL = "https://address.invalid"
				url = cfg.MyAddressURL
			}
			var permissions []map[string]any
			if tc.protocol != "" {
				permissions = []map[string]any{{"IpProtocol": tc.protocol, "FromPort": tc.from, "ToPort": tc.to,
					"IpRanges": []map[string]string{{"CidrIp": tc.cidr}}}}
			}
			groups := jsonText(t, map[string]any{"SecurityGroups": []map[string]any{{"IpPermissions": permissions}}})
			fake := &boxexec.Fake{Handlers: []boxexec.Handler{
				reply("curl", "-fsS", " \n"+ip+"\n"),
				reply("aws", "ec2 describe-security-groups", groups),
				reply("aws", "ec2 authorize-security-group-ingress", "{}"),
			}}
			p := New(cfg, fake, demoOptions()).(*provider)
			if err := p.ensureIngress(context.Background()); err != nil {
				t.Fatal(err)
			}
			curl := oneCall(t, fake, "curl")
			wantArgs(t, curl.Args, []string{"-fsS", "--max-time", "8", url})
			checkEnv(t, curl.Env, nil)
			describe := oneCall(t, fake, "aws", "describe-security-groups")
			wantArgs(t, describe.Args, []string{"ec2", "describe-security-groups", "--group-ids", cfg.SecurityGroup,
				"--output", "json"})
			authorize := fake.CallsMatching("aws", "authorize-security-group-ingress")
			if tc.present {
				if len(authorize) != 0 || len(fake.Calls) != 2 {
					t.Fatal("existing ingress was authorized again")
				}
			} else {
				if len(authorize) != 1 || len(fake.Calls) != 3 {
					t.Fatal("missing ingress was not added exactly once")
				}
				wantArgs(t, authorize[0].Args, []string{"ec2", "authorize-security-group-ingress", "--group-id", cfg.SecurityGroup,
					"--protocol", "tcp", "--port", "22", "--cidr", ip + "/32", "--output", "json"})
			}
			for _, call := range fake.CallsMatching("aws") {
				for _, arg := range call.Args {
					if arg == "create-security-group" || arg == "delete-security-group" {
						t.Fatal("ingress changed security groups")
					}
				}
			}
		})
	}
}

func TestIngressBadAddress(t *testing.T) {
	bad := []string{"", "not-an-address", "::1", "1.2.3", "127.0.0.1/32",
		strings.Join([]string{"127", "0", "0", "256"}, "."),
		strings.Join([]string{"127", "00", "0", "1"}, "."),
		strings.Join([]string{"127", "0", "0", "+1"}, "."),
		strings.Join([]string{"127", "0", "0", "-1"}, "."),
		strings.Join([]string{"127", "0", "0", "1\n" + "extra"}, "."),
	}
	for i, address := range bad {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			fake := &boxexec.Fake{Handlers: []boxexec.Handler{reply("curl", "-fsS", address)}}
			err := New(demoConfig(), fake, demoOptions()).(*provider).ensureIngress(context.Background())
			wantKind(t, err, boxcore.KindOther)
			if len(fake.Calls) != 1 || len(fake.CallsMatching("aws")) != 0 ||
				address != "" && strings.Contains(err.Error(), address) {
				t.Fatal("bad address leaked or reached AWS")
			}
		})
	}
}

func TestIngressFailures(t *testing.T) {
	for _, phase := range []string{"curl-exit", "curl-runner", "groups-json", "groups-empty", "authorize"} {
		t.Run(phase, func(t *testing.T) {
			fake := demoFake(t)
			kind, count := boxcore.KindOther, 1
			switch phase {
			case "curl-exit", "curl-runner":
				fake.Handlers = []boxexec.Handler{{Name: "curl", Respond: func(boxexec.Cmd, int) (boxexec.Result, error) {
					if phase == "curl-runner" {
						return boxexec.Result{Code: -1}, errors.New("curl-private-demo")
					}
					return boxexec.Result{Code: 22, Stdout: []byte("curl-private-demo")}, nil
				}}}
			case "groups-json", "groups-empty":
				count = 2
				text := "{"
				if phase == "groups-empty" {
					text, kind = `{"SecurityGroups":[]}`, boxcore.KindNotFound
				}
				fake.Handlers = []boxexec.Handler{reply("curl", "-fsS", "127.0.0.1"),
					reply("aws", "describe-security-groups", text)}
			case "authorize":
				count, kind = 3, boxcore.KindDenied
				fake.Handlers = []boxexec.Handler{reply("curl", "-fsS", "127.0.0.1"),
					reply("aws", "describe-security-groups", `{"SecurityGroups":[{}]}`),
					{Name: "aws", ArgsContain: []string{"authorize-security-group-ingress"},
						Respond: func(boxexec.Cmd, int) (boxexec.Result, error) {
							return boxexec.Result{Code: 255, Stderr: []byte(awsFailure("AccessDenied", "refused"))}, nil
						}},
				}
			}
			err := New(demoConfig(), fake, demoOptions()).(*provider).ensureIngress(context.Background())
			wantKind(t, err, kind)
			if len(fake.Calls) != count || strings.Contains(err.Error(), "curl-private-demo") {
				t.Fatal("ingress failure was swallowed or exposed private output")
			}
		})
	}
}
