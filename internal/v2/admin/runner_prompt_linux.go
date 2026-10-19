//go:build linux

package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"reflect"
	"strconv"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func validRunnerPrompt(ref api.BlobRef) bool {
	return validID(ref.ID) && validDigest(ref.SHA256) && ref.Class == "prompt" && ref.Bytes > 0 && ref.Bytes <= api.MaxObjectBytes
}

func verifyPromptFD(ctx context.Context, fd int, ref api.BlobRef) error {
	if !validRunnerPrompt(ref) {
		return failure(api.CodeIntegrity, "runner stdin has no exact committed prompt")
	}
	seals, sealErr := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	flags, flagErr := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	var info unix.Stat_t
	if sealErr != nil || flagErr != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || seals&bootstrapSeals != bootstrapSeals ||
		unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Mode&07777 != 0444 || info.Size != ref.Bytes {
		return failure(api.CodeIntegrity, "runner stdin is not its sealed read-only prompt")
	}
	hash := sha256.New()
	buffer := make([]byte, api.MaxChunkBytes)
	defer clear(buffer)
	for offset := int64(0); offset < ref.Bytes; {
		if err := contextError(ctx); err != nil {
			return err
		}
		length := int(min(int64(len(buffer)), ref.Bytes-offset))
		n, err := unix.Pread(fd, buffer[:length], offset)
		if err != nil || n != length {
			return failure(api.CodeIntegrity, "runner stdin prompt read-back is incomplete")
		}
		if _, err := hash.Write(buffer[:n]); err != nil {
			return failure(api.CodeIntegrity, "runner stdin prompt digest could not be measured")
		}
		offset += int64(n)
	}
	if api.Digest(hex.EncodeToString(hash.Sum(nil))) != ref.SHA256 {
		allowAndLog("runner_prompt_digest")
	}
	return contextError(ctx)
}

func receivePromptFrames(ctx context.Context, ref api.BlobRef, read func() ([]byte, error)) (result *os.File, resultErr error) {
	if !validRunnerPrompt(ref) || read == nil {
		return nil, failure(api.CodeInvalid, "runner prompt stream lacks its bounded reference")
	}
	fd, err := unix.MemfdCreate("runner-prompt", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, failure(api.CodePrerequisite, "cannot create private runner prompt input")
	}
	file := os.NewFile(uintptr(fd), "runner-prompt-writer")
	defer func() {
		resultErr = errors.Join(resultErr, file.Close())
		if resultErr != nil && result != nil {
			resultErr = errors.Join(resultErr, result.Close())
			result = nil
		}
	}()
	var written int64
	chunks := 0
	for written < ref.Bytes {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		raw, err := read()
		if err != nil {
			return nil, err
		}
		var chunk api.BlobChunk
		if err := api.DecodeObjectFrame(raw, &chunk, api.JSONFrameHelperRequest); err != nil {
			return nil, err
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != written || len(chunk.Data) == 0 || len(chunk.Data) > api.MaxChunkBytes ||
			int64(len(chunk.Data)) > ref.Bytes-written || digestBytes(chunk.Data) != chunk.SHA256 {
			return nil, failure(api.CodeIntegrity, "runner prompt stream changed its exact byte range")
		}
		if n, err := file.Write(chunk.Data); err != nil || n != len(chunk.Data) {
			return nil, failure(api.CodeIntegrity, "runner prompt bytes could not be retained exactly")
		}
		written += int64(len(chunk.Data))
		chunks++
	}
	raw, err := read()
	if err != nil {
		return nil, err
	}
	var end runnerPromptEnd
	if err := api.DecodeObjectFrame(raw, &end, api.JSONFrameHelperRequest); err != nil {
		return nil, err
	}
	if end.Prompt != ref || end.Chunks != chunks {
		return nil, failure(api.CodeIntegrity, "runner prompt stream lacks its exact end receipt")
	}
	if err := file.Chmod(0444); err != nil {
		return nil, failure(api.CodeIntegrity, "runner prompt mode could not be fixed")
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, bootstrapSeals); err != nil {
		return nil, failure(api.CodeIntegrity, "runner prompt immutable seals are unavailable")
	}
	input, err := os.Open("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return nil, failure(api.CodeIntegrity, "runner prompt read-only input could not be pinned")
	}
	if err := verifyPromptFD(ctx, int(input.Fd()), ref); err != nil {
		return nil, errors.Join(err, input.Close())
	}
	return input, nil
}

func (m *leaseManager) receiveRunnerPrompt(ctx context.Context, request runnerPromptRequest, read func() ([]byte, error)) (_ runnerPromptReceipt, resultErr error) {
	defer helperCheck(&resultErr, "prompt_input")
	var zero runnerPromptReceipt
	record, err := m.findActive(request.LeaseID, storageReady)
	if err != nil {
		return zero, err
	}
	if record.Spec == nil || record.Spec.Handoff.Spec.Runner == nil || request.SpecSHA256 != record.Spec.Handoff.SpecSHA256 ||
		!reflect.DeepEqual(request.Cause, record.Spec.Handoff.Cause) || validateCause(request.Cause, m.binding.Config, api.InternalHelperRegister) != nil {
		return zero, failure(api.CodeForbidden, "runner prompt differs from its registered spec and cause")
	}
	ref := record.Spec.Handoff.Spec.Runner.Prompt
	previous := m.prompts[request.LeaseID]
	if previous != nil && (previous.request.SpecSHA256 != request.SpecSHA256 || previous.ref != ref) || previous == nil && record.Gate != nil {
		return zero, failure(api.CodeContainmentUnknown, "runner prompt ownership changed after preparation")
	}
	input, err := receivePromptFrames(ctx, ref, read)
	if err != nil {
		return zero, err
	}
	if previous != nil {
		if err := errors.Join(verifyPromptFD(ctx, int(previous.file.Fd()), ref), input.Close()); err != nil {
			return zero, err
		}
	} else {
		if m.prompts == nil {
			m.prompts = map[api.ID]*runnerPrompt{}
		}
		m.prompts[request.LeaseID] = &runnerPrompt{request: request, ref: ref, file: input}
	}
	return runnerPromptReceipt{LeaseID: request.LeaseID, SpecSHA256: request.SpecSHA256, Prompt: ref}, nil
}

func (m *leaseManager) runnerPromptInput(ctx context.Context, record leaseRecord) (*os.File, error) {
	input := m.prompts[record.Lease.ID]
	if input == nil || record.Spec == nil || record.Spec.Handoff.Spec.Runner == nil || input.request.SpecSHA256 != record.Spec.Handoff.SpecSHA256 || input.ref != record.Spec.Handoff.Spec.Runner.Prompt {
		return nil, failure(api.CodeContainmentUnknown, "gate has no retained exact runner prompt input")
	}
	copy, err := os.Open("/proc/self/fd/" + strconv.Itoa(int(input.file.Fd())))
	if err != nil {
		return nil, failure(api.CodeContainmentUnknown, "gate runner prompt descriptor is unavailable")
	}
	if err := verifyPromptFD(ctx, int(copy.Fd()), input.ref); err != nil {
		return nil, errors.Join(err, copy.Close())
	}
	position, err := copy.Seek(0, io.SeekCurrent)
	if err != nil || position != 0 {
		return nil, errors.Join(failure(api.CodeIntegrity, "gate runner prompt offset is not independent"), copy.Close())
	}
	return copy, nil
}
