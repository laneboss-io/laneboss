//go:build linux

package wire

import (
	"errors"
	"os"
	"reflect"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// RetainLaneDescriptors duplicates only the sealed binding and pinned socket
// for the explicit child mappings of a cooperative subprocess launcher.
// There is no ambient FD enumeration or forwarding of helper/control handles.
func RetainLaneDescriptors(config, version string) (files []InheritedFile, resultErr error) {
	bindingFD, err := ProjectedDescriptor(LaneBindingPath)
	if err != nil {
		return nil, err
	}
	copyFD, err := unix.FcntlInt(uintptr(bindingFD), unix.F_DUPFD_CLOEXEC, 6)
	if err != nil {
		return nil, bindingError("cannot retain the inherited lane binding")
	}
	files = append(files, InheritedFile{FD: bindingFD, File: os.NewFile(uintptr(copyFD), "inherited-lane-binding")})
	defer func() {
		if resultErr != nil {
			for _, item := range files {
				resultErr = errors.Join(resultErr, item.File.Close())
			}
			files = nil
		}
	}()
	binding, err := readBindingFD(copyFD, config, version, api.EndpointLane, LaneSocketPath)
	if err != nil {
		return files, err
	}
	current, err := ReadBinding(LaneBindingPath, config, version)
	if err != nil || !reflect.DeepEqual(current, binding) {
		return files, errors.Join(bindingError("lane binding changed during child descriptor handoff"), err)
	}
	endpoint, err := PinEndpoint(LaneBindingPath, binding)
	if err != nil {
		return files, err
	}
	defer func() { resultErr = errors.Join(resultErr, endpoint.Close()) }()
	socketFD, err := ProjectedDescriptor(LaneSocketPath)
	if err != nil {
		return files, err
	}
	if err := endpoint.check(); err != nil {
		return files, err
	}
	copyFD, err = unix.FcntlInt(endpoint.file.Fd(), unix.F_DUPFD_CLOEXEC, 6)
	if err != nil {
		return files, bindingError("cannot retain the inherited lane socket")
	}
	files = append(files, InheritedFile{FD: socketFD, File: os.NewFile(uintptr(copyFD), "inherited-lane-socket")})
	return files, nil
}
