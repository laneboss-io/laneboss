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
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/service"
)

type releaseCanaryFrame struct {
	Method string          `json:"method"`
	Input  json.RawMessage `json:"input"`
}

type releaseCanaryReply struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  *api.Error      `json:"error,omitempty"`
}

func TestNaturalReleaseCanary(t *testing.T) {
	naturalReleaseTest(t, "TestNaturalReleaseCanary", service.ExerciseNaturalReleaseCanary)
}

func TestStoppedCaptureMonitorNative(t *testing.T) {
	naturalReleaseTest(t, "TestStoppedCaptureMonitorNative", service.ExerciseStoppedCaptureCanary)
}

func TestCapturePlanningDeadlineNative(t *testing.T) {
	naturalReleaseTest(t, "TestCapturePlanningDeadlineNative", lifecycle.ExerciseCaptureLifetimeCanary)
}

func naturalReleaseTest(t *testing.T, name string, driver func(*testing.T, func(string, any, any) error)) {
	if os.Args[len(os.Args)-1] == "natural-release-child" {
		input, output := os.NewFile(3, "native-helper-replies"), os.NewFile(4, "native-helper-requests")
		defer input.Close()
		defer output.Close()
		decoder, encoder := json.NewDecoder(input), json.NewEncoder(output)
		driver(t, func(method string, value, target any) error {
			raw, err := json.Marshal(value)
			if err != nil {
				return err
			}
			if err := encoder.Encode(releaseCanaryFrame{Method: method, Input: raw}); err != nil {
				return err
			}
			var reply releaseCanaryReply
			if err := decoder.Decode(&reply); err != nil {
				return err
			}
			if reply.Error != nil {
				t.Logf("native helper %s refused: %v", method, reply.Error)
				return reply.Error
			}
			return json.Unmarshal(reply.Result, target)
		})
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("natural release canary requires disposable Linux root")
	}
	if os.Args[len(os.Args)-1] != "natural-release-root" {
		if name == "TestStoppedCaptureMonitorNative" {
			admin.RunStoppedCaptureUnit(t)
		} else if name == "TestCapturePlanningDeadlineNative" {
			admin.RunCaptureLifetimeUnit(t)
		} else if name == "TestGrantCascadeNative" {
			admin.RunGrantCascadeUnit(t)
		} else if name == "TestSealedDelegationNative" {
			admin.RunSealedDelegationUnit(t)
		} else {
			admin.RunNaturalReleaseUnit(t)
		}
		return
	}
	parent := admin.NewNaturalReleaseNative(t)
	homeParent := filepath.Join("/run/laneboss-v2", os.Args[len(os.Args)-2])
	if err := os.MkdirAll(homeParent, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(homeParent, 0, 61000); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(homeParent, 0710); err != nil {
		t.Fatal(err)
	}
	home, err := os.MkdirTemp(homeParent, "lb-natural-release-")
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
	// Copy the actual test executable into a root-owned traversable location;
	// the service UID cannot traverse Go's temporary root build directory.
	executable, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(home, "canary")
	if err := os.WriteFile(binary, executable, 0555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(binary, 0555); err != nil {
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
	command := exec.Command(binary, "-test.run=^"+name+"$", "-test.timeout=90s", "--", "natural-release-child")
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
		var frame releaseCanaryFrame
		if err := decoder.Decode(&frame); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal("native helper request failed", err)
		}
		var result any
		var callErr error
		if frame.Method == "grant-stop" {
			result, callErr = parent.GrantCascadeStop(frame.Input)
		} else {
			result, callErr = parent.Exchange(frame.Method, frame.Input)
		}
		var reply releaseCanaryReply
		if callErr != nil {
			var typed *api.Error
			if errors.As(callErr, &typed) {
				reply.Error = typed
			} else {
				reply.Error = &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-admin", Message: callErr.Error()}
			}
		} else {
			reply.Result, err = json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := encoder.Encode(reply); err != nil {
			t.Fatal("native helper reply failed", err)
		}
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("natural release child failed: %v\n%s", err, output.String())
	}
	t.Log(output.String())
}
