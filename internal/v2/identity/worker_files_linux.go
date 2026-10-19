package identity

import (
	"io"
	"os"
	"reflect"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

type workerFilePin struct {
	device uint64
	inode  uint64
	bytes  int64
}

// Read the actual borrowed anonymous handles, not a helper's copied byte slice
// or a pathname supplied by a request. Kernel seals exclude writable aliases.
func workerFileBytes(file *os.File) ([]byte, workerFilePin, error) {
	var pin workerFilePin
	if file == nil {
		return nil, pin, refusal(api.CodeUnauthenticated, "worker descriptor is missing")
	}
	fd := int(file.Fd())
	var stat unix.Stat_t
	mode, modeErr := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	flags, flagErr := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	seals, sealErr := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	want := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if unix.Fstat(fd, &stat) != nil || modeErr != nil || flagErr != nil || sealErr != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0444 || stat.Nlink != 0 || stat.Size <= 0 || stat.Size > api.MaxFrameBytes ||
		mode&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.FD_CLOEXEC == 0 || seals&want != want {
		return nil, pin, refusal(api.CodeUnauthenticated, "worker descriptor is not a sealed immutable read-only object")
	}
	pin = workerFilePin{device: uint64(stat.Dev), inode: stat.Ino, bytes: stat.Size}
	data := make([]byte, int(stat.Size))
	if n, err := file.ReadAt(data, 0); err != nil || n != len(data) {
		return nil, pin, refusal(api.CodeIntegrity, "worker descriptor could not be read exactly")
	}
	var extra [1]byte
	if n, err := file.ReadAt(extra[:], stat.Size); n != 0 || err != io.EOF {
		return nil, pin, refusal(api.CodeIntegrity, "worker descriptor exceeds its pinned bytes")
	}
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || uint64(after.Dev) != pin.device || after.Ino != pin.inode || after.Size != pin.bytes {
		return nil, pin, refusal(api.CodeIntegrity, "worker descriptor changed during verification")
	}
	return data, pin, nil
}

func checkWorkerFiles(input, endpoint *os.File, ref api.BlobRef, expected api.InstalledBinding) error {
	data, inputPin, err := workerFileBytes(input)
	if err != nil {
		return err
	}
	if int64(len(data)) != ref.Bytes || digestBytes(data) != ref.SHA256 {
		return refusal(api.CodeIntegrity, "worker input descriptor differs from its retained immutable object")
	}
	raw, endpointPin, err := workerFileBytes(endpoint)
	if err != nil {
		return err
	}
	if inputPin.device == endpointPin.device && inputPin.inode == endpointPin.inode {
		return refusal(api.CodeIntegrity, "worker input and endpoint reuse one object")
	}
	var binding api.InstalledBinding
	if api.DecodeObject(raw, &binding) != nil || !reflect.DeepEqual(binding, expected) {
		return refusal(api.CodeIntegrity, "worker endpoint descriptor differs from its protected installation")
	}
	return nil
}
