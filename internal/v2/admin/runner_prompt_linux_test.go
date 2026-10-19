//go:build linux

package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func init() {
	if len(os.Args) == 4 && os.Args[1] == "admin-runner-stdin" {
		size, err := strconv.ParseInt(os.Args[2], 10, 64)
		if err != nil {
			os.Exit(151)
		}
		ref := api.BlobRef{ID: "prompt-fixture", Class: "prompt", Bytes: size, SHA256: api.Digest(os.Args[3])}
		if verifyPromptFD(context.Background(), 0, ref) != nil {
			os.Exit(152)
		}
		if _, err := io.Copy(os.Stdout, os.Stdin); err != nil {
			os.Exit(153)
		}
		os.Exit(0)
	}
}

func promptFrames(t *testing.T, data []byte) (api.BlobRef, [][]byte) {
	t.Helper()
	ref := api.BlobRef{ID: "prompt-fixture", Class: "prompt", Bytes: int64(len(data)), SHA256: digestBytes(data)}
	var encoded bytes.Buffer
	if err := writeHelperInput(&encoded, runnerPromptTransfer{Ref: ref, Data: data}); err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(encoded.Bytes())
	var frames [][]byte
	for reader.Len() != 0 {
		frame, err := wire.ReadFrame(reader)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, frame)
	}
	return ref, frames
}

func promptFrameReader(frames [][]byte) func() ([]byte, error) {
	index := 0
	return func() ([]byte, error) {
		if index >= len(frames) {
			return nil, io.EOF
		}
		frame := frames[index]
		index++
		return frame, nil
	}
}

func promptInputFixture(t *testing.T, data []byte) (*os.File, api.BlobRef) {
	t.Helper()
	ref, frames := promptFrames(t, data)
	input, err := receivePromptFrames(context.Background(), ref, promptFrameReader(frames))
	if err != nil {
		t.Fatal("actual prompt stream could not retain its sealed input", err)
	}
	t.Cleanup(func() {
		if err := input.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error(err)
		}
	})
	return input, ref
}

func TestRunnerPromptFrames(t *testing.T) {
	data := make([]byte, api.MaxFrameBytes+37)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"valid", "offset", "object", "chunk-hash", "total-hash", "end-ref", "end-count", "truncated", "duplicate", "null"} {
		t.Run(fault, func(t *testing.T) {
			ref, frames := promptFrames(t, data)
			var first api.BlobChunk
			if err := api.DecodeObject(frames[0], &first); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "offset":
				first.Offset++
			case "object":
				first.ObjectID = "other-prompt"
			case "chunk-hash":
				first.SHA256 = testDigest("other-chunk")
			case "total-hash":
				ref.SHA256 = testDigest("other-total")
				var end runnerPromptEnd
				if err := api.DecodeObject(frames[len(frames)-1], &end); err != nil {
					t.Fatal(err)
				}
				end.Prompt = ref
				encoded, err := json.Marshal(end)
				if err != nil {
					t.Fatal(err)
				}
				frames[len(frames)-1] = encoded
			case "end-ref", "end-count":
				var end runnerPromptEnd
				if err := api.DecodeObject(frames[len(frames)-1], &end); err != nil {
					t.Fatal(err)
				}
				if fault == "end-ref" {
					end.Prompt.ID = "other-prompt"
				} else {
					end.Chunks++
				}
				encoded, err := json.Marshal(end)
				if err != nil {
					t.Fatal(err)
				}
				frames[len(frames)-1] = encoded
			case "truncated":
				frames = frames[:len(frames)-1]
			case "duplicate":
				frames[0] = append(append([]byte{}, frames[0][:len(frames[0])-1]...), []byte(",\"offset\":0}")...)
			case "null":
				frames[0] = []byte("null")
			}
			if fault == "offset" || fault == "object" || fault == "chunk-hash" {
				encoded, err := json.Marshal(first)
				if err != nil {
					t.Fatal(err)
				}
				frames[0] = encoded
			}
			allowed := captureAllowed(t)
			input, err := receivePromptFrames(context.Background(), ref, promptFrameReader(frames))
			if fault == "total-hash" {
				// Owner R181-R192: the whole-prompt digest re-verification is allowed and logged; each chunk digest
				// is still verified (the chunk-hash case keeps refusing).
				if err != nil || input == nil || !slices.Equal(allowed(), []string{"runner_prompt_digest"}) {
					t.Fatal("whole-prompt digest re-verification was not allowed and logged", err, allowed())
				}
				if closeErr := input.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
				return
			}
			if fault != "valid" {
				if input != nil {
					if closeErr := input.Close(); closeErr != nil {
						t.Fatal(closeErr)
					}
				}
				if err == nil || input != nil {
					t.Fatal("acceptance: changed runner prompt stream became a usable input")
				}
				return
			}
			if err != nil || input == nil || len(allowed()) != 0 {
				t.Fatal("acceptance: exact multi-frame runner prompt was refused", err, allowed())
			}
			defer input.Close()
			actual, err := io.ReadAll(input)
			if err != nil || !bytes.Equal(actual, data) || verifyPromptFD(context.Background(), int(input.Fd()), ref) != nil {
				t.Fatal("acceptance: runner prompt lost its sealed exact bytes or repeatable reads", err)
			}
			if _, err := input.Write([]byte("changed")); err == nil {
				t.Fatal("acceptance: runner prompt input remained writable")
			}
		})
	}
}

func TestRunnerPromptStdin(t *testing.T) {
	data := make([]byte, api.MaxChunkBytes+19)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	input, ref := promptInputFixture(t, data)
	manager := &leaseManager{prompts: map[api.ID]*runnerPrompt{"prompt-lease": {request: runnerPromptRequest{SpecSHA256: testDigest("spec")}, ref: ref, file: input}}}
	record := leaseRecord{Lease: api.HelperLease{ID: "prompt-lease"}, Spec: &specRegistration{Handoff: api.PreparedSpecHandoff{SpecSHA256: testDigest("spec"), Spec: api.LaunchSpec{Runner: &api.RunnerPlan{Prompt: ref}}}}}
	first, err := manager.runnerPromptInput(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := first.Read(make([]byte, 7)); err != nil {
		t.Fatal(err)
	}
	second, err := manager.runnerPromptInput(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/proc/self/exe", "admin-runner-stdin", strconv.FormatInt(ref.Bytes, 10), string(ref.SHA256))
	command.Env, command.Stdin = []string{}, second
	actual, err := command.Output()
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatal("acceptance: actual runner stdin lost its sealed bytes or independent initial offset", err)
	}
	changed := record
	changed.Spec = &specRegistration{Handoff: record.Spec.Handoff}
	changed.Spec.Handoff.SpecSHA256 = testDigest("other-spec")
	if copy, err := manager.runnerPromptInput(context.Background(), changed); err == nil || copy != nil {
		if copy != nil {
			if closeErr := copy.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
		}
		t.Fatal("acceptance: runner stdin ignored its retained spec identity")
	}
	flags, err := unix.FcntlInt(input.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("acceptance: helper prompt source became inheritable", err)
	}
	if err := manager.closeRunnerPrompt(record.Lease.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Stat(); !errors.Is(err, os.ErrClosed) || manager.prompts[record.Lease.ID] != nil {
		t.Fatal("acceptance: collected runner prompt retained its helper owner", err)
	}
}
