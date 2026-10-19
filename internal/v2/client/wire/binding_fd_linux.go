//go:build linux

package wire

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// Each fixed projection is an inherited immutable descriptor, never a
// memfd bind source. Shape/seals are not authentication: the native endpoint
// still verifies the actual peer, containment, lease and current claim.
func readProjectedBinding(path, config, version string) (api.InstalledBinding, bool, error) {
	var binding api.InstalledBinding
	class, socket := api.EndpointWorker, WorkerSocketPath
	switch path {
	case WorkerBindingPath:
	case LaneBindingPath:
		// A regular administrator-owned human binding still uses the ordinary
		// protected-file checks. Only a descriptor link selects lane input.
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			return binding, false, nil
		}
		class, socket = api.EndpointLane, LaneSocketPath
	default:
		return binding, false, nil
	}
	fd, err := ProjectedDescriptor(path)
	if err != nil {
		return binding, true, err
	}
	binding, err = readBindingFD(fd, config, version, class, socket)
	return binding, true, err
}

func validateRegularProjection(binding api.InstalledBinding) error {
	if binding.Class == api.EndpointLane {
		return bindingError("lane binding requires its fixed sealed inherited projection")
	}
	return nil
}

// ProjectedDescriptor accepts only the exact descriptor-link grammar emitted
// by the fixed bootstrap. It does not open or follow an arbitrary pathname.
func ProjectedDescriptor(path string) (int, error) {
	switch path {
	case LaneBindingPath, LaneSocketPath, WorkerBindingPath, WorkerSocketPath, WorkerInputPath:
	default:
		return -1, bindingError("descriptor projection is not a fixed namespace destination")
	}
	link, err := os.Readlink(path)
	if err != nil || !strings.HasPrefix(link, "/proc/self/fd/") {
		return -1, bindingError("projection is not its fixed inherited descriptor")
	}
	word := strings.TrimPrefix(link, "/proc/self/fd/")
	fd, err := strconv.Atoi(word)
	if err != nil || fd < 6 || strconv.Itoa(fd) != word {
		return -1, bindingError("projection has an invalid inherited descriptor number")
	}
	return fd, nil
}

func readWorkerBindingFD(fd int, config, version string) (api.InstalledBinding, error) {
	return readBindingFD(fd, config, version, api.EndpointWorker, WorkerSocketPath)
}

func readBindingFD(fd int, config, version string, class api.EndpointClass, socket string) (api.InstalledBinding, error) {
	var binding api.InstalledBinding
	data, err := sealedDescriptorBytes(fd)
	if err != nil {
		return binding, err
	}
	if Decode(data, &binding) != nil || binding.Class != class || binding.Socket != socket {
		return binding, bindingError("binding differs from its fixed sealed endpoint projection")
	}
	if err := api.ValidateBinding(binding, config, version); err != nil {
		return binding, err
	}
	return binding, nil
}

// ReadWorkerInput binds the inherited bytes to the authenticated lease's
// immutable input reference. It preserves whitespace and never changes offset.
func ReadWorkerInput(ref api.BlobRef) ([]byte, error) {
	fd, err := ProjectedDescriptor(WorkerInputPath)
	if err != nil {
		return nil, err
	}
	return readWorkerInputFD(fd, ref)
}

func readWorkerInputFD(fd int, ref api.BlobRef) ([]byte, error) {
	if !ValidID(string(ref.ID)) || ref.Bytes < 1 || ref.Bytes > api.MaxFrameBytes ||
		ref.Class != "materialize_input" && ref.Class != "worker_input" && ref.Class != "archive_input" && ref.Class != "usage_input" && ref.Class != "channel_input" {
		return nil, bindingError("worker has no exact immutable job input reference")
	}
	data, err := sealedDescriptorBytes(fd)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	if int64(len(data)) != ref.Bytes || api.Digest(hex.EncodeToString(digest[:])) != ref.SHA256 {
		return nil, bindingError("inherited worker input differs from its authenticated lease")
	}
	return data, nil
}

func sealedDescriptorBytes(fd int) (data []byte, resultErr error) {
	owned, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 6)
	if err != nil {
		return nil, bindingError("sealed inherited descriptor is unavailable")
	}
	defer func() { resultErr = errors.Join(resultErr, unix.Close(owned)) }()
	seals, err := unix.FcntlInt(uintptr(owned), unix.F_GET_SEALS, 0)
	var info unix.Stat_t
	const required = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if err != nil || seals&required != required || unix.Fstat(owned, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG ||
		info.Mode&07777 != 0444 || info.Size < 1 || info.Size > api.MaxFrameBytes {
		return nil, bindingError("inherited input is not exactly sealed and read-only")
	}
	data = make([]byte, info.Size)
	n, err := unix.Pread(owned, data, 0)
	if err != nil && err != io.EOF || int64(n) != info.Size {
		return nil, bindingError("cannot read exact inherited input bytes")
	}
	return data, nil
}
