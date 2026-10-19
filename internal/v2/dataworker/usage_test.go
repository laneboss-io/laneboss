//go:build linux

package dataworker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/secrets"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 0 && os.Args[0] == "claudock" {
		if strings.Join(os.Args[1:], " ") != "usage --max-age 0" {
			os.Exit(64)
		}
		raw, err := os.ReadFile("usage.tsv")
		if err != nil {
			os.Exit(65)
		}
		code, err := os.ReadFile("usage.exit")
		if err != nil {
			os.Exit(66)
		}
		exit, err := strconv.Atoi(string(code))
		if err != nil || exit < 0 || exit > 125 {
			os.Exit(67)
		}
		if _, err := os.Stdout.Write(raw); err != nil {
			os.Exit(68)
		}
		os.Exit(exit)
	}
	os.Exit(m.Run())
}

type usagePorts struct {
	*archivePorts
	fault string
}

func (p *usagePorts) WorkerInput(ctx context.Context, scope api.Scope, q api.WorkerInputRequest) (api.WorkerJobInput, error) {
	if p.fault == "transport" {
		return api.WorkerJobInput{}, errors.New("usage input transport failed")
	}
	input, err := p.archivePorts.WorkerInput(ctx, scope, q)
	if p.fault == "input" {
		input.Bytes = append(append([]byte{}, input.Bytes...), '\n')
	}
	return input, err
}

func (p *usagePorts) WorkerResult(ctx context.Context, scope api.Scope, q api.WorkerResultSubmission) (api.WorkerResultReceipt, error) {
	if p.fault == "append" {
		return api.WorkerResultReceipt{}, errors.New("usage result transport failed")
	}
	receipt, err := p.archivePorts.WorkerResult(ctx, scope, q)
	if p.fault == "ack" {
		receipt.Result.SHA256 = manifest.Hash([]byte("changed receipt"))
	}
	return receipt, err
}

func usageFixture(t *testing.T, fault string) (UsageJob, *usagePorts, []byte) {
	t.Helper()
	base, original := archiveFixture(t, "valid")
	p := base.Principal
	p.Lease.Kind = "usage"
	p.Claim.Record.Effect.Worker.Kind = "usage"
	p.Peer.HostUID, p.Peer.HostGID, p.Peer.HostPID = uint32(os.Geteuid()), uint32(os.Getegid()), os.Getpid()
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(stat[strings.LastIndex(string(stat), ")")+2:]))
	p.Peer.ProcessGeneration = fields[19]
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	p.BootID = strings.TrimSpace(string(boot))
	p.Peer.ProcessGeneration = p.BootID + ":" + fields[19]
	p.Record.HostUID, p.Record.ProcessGeneration = p.Peer.HostUID, p.Peer.ProcessGeneration
	p.Endpoint.ServiceUID = p.Peer.HostUID + 1000
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	program, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	execPath := filepath.Join(root, "query")
	if err := os.WriteFile(execPath, program, 0500); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Open(execPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := executable.Close(); err != nil {
			t.Error(err)
		}
	})
	home, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := home.Close(); err != nil {
			t.Error(err)
		}
	})
	raw := make([]byte, 71)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usage.tsv"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	exit := "0"
	if fault == "nonzero" {
		exit = "23"
	}
	if err := os.WriteFile(filepath.Join(root, "usage.exit"), []byte(exit), 0600); err != nil {
		t.Fatal(err)
	}
	selected := api.UsageCredentialInput{Schema: "laneboss.usage-input.v1", VendorProfile: "synthetic-query",
		Request: api.UsageWindowRequest{Target: p.Lease.Target, OperationID: p.Lease.OperationID, RuntimeManifest: p.Lease.RuntimeManifest,
			Executable: api.Executable{ID: "query", SHA256: manifest.Hash(program), Version: "fixture"}}}
	input, err := json.Marshal(selected)
	if err != nil {
		t.Fatal(err)
	}
	p.Lease.Input.Class, p.Lease.Input.SHA256, p.Lease.Input.Bytes = "usage_input", manifest.Hash(input), int64(len(input))
	p.Claim.Record.Effect.Worker.Input = p.Lease.Input
	original.input.Kind, original.input.Input, original.input.Bytes = "usage", p.Lease.Input, input
	ports := &usagePorts{archivePorts: original, fault: fault}
	return UsageJob{Principal: p, Scope: base.Scope, Bootstrap: ports, Executable: executable, Home: home, Clock: base.Clock}, ports, raw
}

func TestUsageWorker(t *testing.T) {
	for _, fault := range []string{"valid", "nonzero", "input", "transport", "append", "ack", "scope"} {
		t.Run(fault, func(t *testing.T) {
			job, ports, raw := usageFixture(t, fault)
			if fault == "scope" {
				job.Scope.Actor.Kind = "service"
			}
			args := []string{"--binding", "/runtime/laneboss-worker.json", "--lease", string(job.Principal.Lease.ID)}
			receipt, err := RunInternalJob(context.Background(), "example", args, job)
			if fault != "valid" && fault != "nonzero" {
				if err == nil {
					t.Fatal("usage worker accepted", fault)
				}
				if (fault == "input" || fault == "transport" || fault == "scope") && ports.submissions != 0 {
					t.Fatal("failed input submitted a result")
				}
				return
			}
			if err != nil || receipt.Result.Class != "worker_result" || ports.submissions != 1 {
				t.Fatal("usage worker did not append its actual command result", err)
			}
			var result secrets.UsageCommandResult
			if err := api.DecodeObject(ports.result, &result); err != nil {
				t.Fatal(err)
			}
			exit := 0
			if fault == "nonzero" {
				exit = 23
			}
			if !bytes.Equal(result.Raw, raw) || result.ExitCode != exit || result.ObservedAt == "" {
				t.Fatal("usage worker replaced command bytes or measured exit")
			}
		})
	}
}
