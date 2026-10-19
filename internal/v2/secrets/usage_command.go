package secrets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

type usageBuffer struct {
	data     []byte
	limit    int
	exceeded bool
}

func (b *usageBuffer) Write(data []byte) (int, error) {
	if len(data) > b.limit-len(b.data) {
		b.exceeded = true
		return 0, wire.Error(api.CodeBudget, "outside usage output exceeds its private byte bound")
	}
	b.data = append(b.data, data...)
	return len(data), nil
}

// RunUsageCommand runs only within the actual separately installed usage worker.
// Handles come from its helper projection, not a request path or passed public
// descriptor. The dispatch adapter retains the result and real append frame.
// This component neither authenticates a vendor nor mounts a login registry.
func RunUsageCommand(ctx context.Context, principal api.WorkerPrincipal, input api.WorkerJobInput, executable, home *os.File, clock api.Clock) (UsageCommandResult, error) {
	var result UsageCommandResult
	if ctx == nil || executable == nil || home == nil || wire.Nil(clock) {
		return result, wire.Error(api.CodePrerequisite, "usage command requires its installed handles clock and context")
	}
	if err := wire.Context(ctx); err != nil {
		return result, err
	}
	bounded, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := api.ValidateWorkerInput(principal, input, clock.Now()); err != nil {
		return result, err
	}
	if principal.Lease.Kind != "usage" {
		return result, wire.Error(api.CodeForbidden, "only the fixed usage worker can run the vendor query")
	}
	if err := verifyUsageProcess(principal); err != nil {
		return result, err
	}
	var selected UsageInput
	if err := api.DecodeObject(input.Bytes, &selected); err != nil {
		return result, err
	}
	if selected.Schema != "laneboss.usage-input.v1" || selected.Request.Target != principal.Lease.Target || selected.Request.OperationID != principal.Lease.OperationID || selected.Request.RuntimeManifest != principal.Lease.RuntimeManifest || !usageName(selected.VendorProfile) {
		return result, wire.Error(api.CodeForbidden, "usage command input differs from its authenticated job")
	}
	info, err := executable.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0222 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() < 4 || info.Size() > 128<<20 {
		return result, wire.Error(api.CodeIntegrity, "usage executable handle is not a bounded installed program")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 && stat.Uid != principal.Peer.HostUID {
		return result, wire.Error(api.CodeIntegrity, "usage executable handle has a foreign owner")
	}
	// A held inode alone does not prevent in-place writes after the hash.
	// Execute the sealed snapshot whose actual bytes are checked below.
	pinnedExecutable, err := snapshotUsageExecutable(executable, info.Size())
	if err != nil {
		return result, err
	}
	defer pinnedExecutable.Close()
	magic := make([]byte, 4)
	if _, err := pinnedExecutable.ReadAt(magic, 0); err != nil || !bytes.Equal(magic, []byte{0x7f, 'E', 'L', 'F'}) {
		return result, wire.Error(api.CodeUnsupported, "usage query requires the installed native Linux binary")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.NewSectionReader(pinnedExecutable, 0, info.Size())); err != nil || api.Digest(hex.EncodeToString(hash.Sum(nil))) != selected.Request.Executable.SHA256 {
		return result, wire.Error(api.CodeIntegrity, "usage executable bytes differ from the enrolled pin")
	}
	if err := wire.Context(bounded); err != nil {
		return result, err
	}
	homeInfo, err := home.Stat()
	if err != nil || !homeInfo.IsDir() || homeInfo.Mode().Perm() != 0700 {
		return result, wire.Error(api.CodeIntegrity, "usage home handle is not private")
	}
	homeStat, ok := homeInfo.Sys().(*syscall.Stat_t)
	if !ok || homeStat.Uid != principal.Peer.HostUID {
		return result, wire.Error(api.CodeForbidden, "usage home does not belong to the confined worker")
	}
	// Held executable and home descriptors prevent a pathname re-resolution.
	command := exec.CommandContext(bounded, "/proc/self/fd/3", "usage", "--max-age", "0")
	command.Args[0] = "claudock"
	command.ExtraFiles = []*os.File{pinnedExecutable, home}
	command.Dir = "/proc/self/fd/" + strconv.FormatUint(uint64(home.Fd()), 10)
	command.Env = []string{"HOME=/proc/self/fd/4", "PATH=/usr/bin:/bin", "XDG_CONFIG_HOME=/proc/self/fd/4/.config", "LANG=C.UTF-8"}
	command.WaitDelay = time.Second
	out, diagnostic := &usageBuffer{limit: api.MaxFrameBytes}, &usageBuffer{limit: 64 * 1024}
	command.Stdout, command.Stderr = out, diagnostic
	defer func() { clear(diagnostic.data) }()
	runErr := command.Run()
	result.Raw = out.data
	result.ObservedAt = api.Timestamp(clock.Now().UTC().Format(time.RFC3339Nano))
	if out.exceeded || diagnostic.exceeded {
		clear(result.Raw)
		return UsageCommandResult{}, wire.Error(api.CodeUnavailable, "outside usage output exceeded its bounded complete result")
	}
	if bounded.Err() != nil {
		clear(result.Raw)
		return UsageCommandResult{}, wire.Context(bounded)
	}
	if command.ProcessState == nil {
		clear(result.Raw)
		return UsageCommandResult{}, wire.Error(api.CodeUnavailable, "outside usage program did not produce a measured exit")
	}
	result.ExitCode = command.ProcessState.ExitCode()
	if runErr != nil {
		var exited *exec.ExitError
		if !errors.As(runErr, &exited) {
			clear(result.Raw)
			return UsageCommandResult{}, wire.Error(api.CodeUnavailable, "outside usage command output or collection failed")
		}
	}
	if err := verifyUsageProcess(principal); err != nil {
		clear(result.Raw)
		return UsageCommandResult{}, err
	}
	return result, nil
}
