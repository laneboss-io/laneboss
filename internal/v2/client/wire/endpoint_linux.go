//go:build linux

package wire

import (
	"errors"
	"os"
	"reflect"
	"strconv"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// PinEndpoint requires the sealed proof whenever the fixed child projection
// is selected. A socket symlink or an InstalledBinding value alone is not proof.
func PinEndpoint(bindingFile string, binding api.InstalledBinding) (*Endpoint, error) {
	if binding.Class == api.EndpointHuman {
		return &Endpoint{path: binding.Socket}, nil
	}
	if binding.Class == api.EndpointLane && bindingFile != LaneBindingPath {
		return nil, bindingError("lane endpoint requires its fixed sealed binding projection")
	}
	if bindingFile != LaneBindingPath && bindingFile != WorkerBindingPath {
		return &Endpoint{path: binding.Socket}, nil
	}
	proof, handled, err := readProjectedBinding(bindingFile, binding.Config, binding.ServiceVersion)
	if err != nil {
		return nil, err
	}
	if !handled || !reflect.DeepEqual(proof, binding) {
		return nil, bindingError("socket projection has no matching sealed binding")
	}
	fd, err := ProjectedDescriptor(binding.Socket)
	if err != nil {
		return nil, err
	}
	endpoint, err := pinEndpointFD(fd, binding)
	if err != nil {
		return nil, err
	}
	// Reconnects retain the same pinned inode and require the original
	// projection to remain intact. No pathname replacement is followed.
	endpoint.check = func() error {
		current, err := ProjectedDescriptor(binding.Socket)
		if err != nil {
			return err
		}
		var projected, held unix.Stat_t
		if unix.Fstat(current, &projected) != nil || unix.Fstat(int(endpoint.file.Fd()), &held) != nil ||
			projected.Dev != held.Dev || projected.Ino != held.Ino || !endpointSocket(projected, binding) || !endpointSocket(held, binding) {
			return bindingError("pinned endpoint projection changed while client was open")
		}
		return nil
	}
	return endpoint, nil
}

func endpointSocket(info unix.Stat_t, binding api.InstalledBinding) bool {
	return info.Mode&unix.S_IFMT == unix.S_IFSOCK && info.Mode&07777 == 0666 && info.Nlink == 1 &&
		info.Uid == binding.MappedServiceUID && info.Gid == binding.MappedServiceGID
}

func pinEndpointFD(fd int, binding api.InstalledBinding) (*Endpoint, error) {
	owned, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 6)
	if err != nil {
		return nil, bindingError("inherited endpoint descriptor is unavailable")
	}
	file := os.NewFile(uintptr(owned), "pinned-service-endpoint")
	flags, err := unix.FcntlInt(uintptr(owned), unix.F_GETFL, 0)
	var info unix.Stat_t
	if err != nil || flags&unix.O_PATH == 0 || unix.Fstat(owned, &info) != nil || !endpointSocket(info, binding) {
		return nil, errors.Join(bindingError("inherited endpoint is not its protected O_PATH socket inode"), file.Close())
	}
	return &Endpoint{file: file, path: "/proc/self/fd/" + strconv.Itoa(owned)}, nil
}
