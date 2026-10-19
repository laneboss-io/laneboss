//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/service"
)

type agentOpenFrame struct {
	Method string          `json:"method"`
	Input  json.RawMessage `json:"input"`
}

type agentOpenReply struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  *api.Error      `json:"error,omitempty"`
}

func TestAgentOwnerNativeCanary(t *testing.T) {
	last := os.Args[len(os.Args)-1]
	if last == "agent-open-child" {
		requests, replies := os.NewFile(3, "agent-open-requests"), os.NewFile(4, "agent-open-replies")
		defer requests.Close()
		defer replies.Close()
		decoder, encoder := json.NewDecoder(requests), json.NewEncoder(replies)
		service.ExerciseAgentOwnerNativeCanary(t, func(method string, value, target any) error {
			raw, err := json.Marshal(value)
			if err != nil {
				return err
			}
			if err := encoder.Encode(agentOpenFrame{Method: method, Input: raw}); err != nil {
				return err
			}
			var reply agentOpenReply
			if err := decoder.Decode(&reply); err != nil {
				return err
			}
			if reply.Error != nil {
				return reply.Error
			}
			return json.Unmarshal(reply.Result, target)
		})
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("agent open canary requires disposable Linux root")
	}
	if last != "agent-open-root" {
		admin.RunAgentOpenUnit(t)
		return
	}
	parent := admin.NewNaturalReleaseNative(t)
	config := os.Args[len(os.Args)-2]
	home, err := os.MkdirTemp(filepath.Join("/var/lib/laneboss-v2/helper", config), "lb-agent-open-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(home); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chown(home, 61000, 61000); err != nil {
		t.Fatal(err)
	}
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(home, "canary")
	if err := os.WriteFile(binary, self, 0555); err != nil {
		t.Fatal(err)
	}
	requests, requestWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer requests.Close()
	replies, replyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer replyWrite.Close()
	command := exec.Command(binary, "-test.run=^TestAgentOwnerNativeCanary$", "-test.timeout=90s", "--", "agent-open-child")
	command.Env = []string{"HOME=" + home}
	command.ExtraFiles = []*os.File{replies, requestWrite}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 61000, Gid: 61000, Groups: []uint32{}}}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := replies.Close(); err != nil {
		t.Fatal(err)
	}
	if err := requestWrite.Close(); err != nil {
		t.Fatal(err)
	}
	decoder, encoder := json.NewDecoder(requests), json.NewEncoder(replyWrite)
	for {
		var frame agentOpenFrame
		if err := decoder.Decode(&frame); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal("agent open helper request failed", err)
		}
		result, callErr := parent.Exchange(frame.Method, frame.Input)
		var reply agentOpenReply
		if callErr != nil {
			var typed *api.Error
			if errors.As(callErr, &typed) {
				reply.Error = typed
			} else {
				reply.Error = &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-admin", Message: callErr.Error()}
			}
		} else if reply.Result, err = json.Marshal(result); err != nil {
			t.Fatal(err)
		}
		if err := encoder.Encode(reply); err != nil {
			t.Fatal("agent open helper reply failed", err)
		}
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("agent open child failed: %v\n%s", err, output.String())
	}
	t.Log(output.String())
}
