//go:build linux && laneboss_partial && laneboss_e2e_authenticator

package admin

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// Only the privileged installed helper enrolls its actual allocation. The
// endpoint is fixed by the installation; no actor supplies a host pathname.
func (m *leaseManager) usageProvider(ctx context.Context, job api.UsageJob, lease api.HelperLease, active bool) error {
	manifest, err := loadInstalledRuntime(ctx, m.binding, job.Lease.RuntimeManifest)
	if err != nil {
		return err
	}
	declared := false
	for _, object := range manifest.Objects {
		declared = declared || object.ID == "wd-run" && object.Role == "watchdog-fixture" && object.Mode == 0444
	}
	if !declared {
		return nil
	}
	service, err := workerServiceBinding(m.binding)
	if err != nil {
		return err
	}
	base := filepath.Join(filepath.Dir(service.Socket), "workers")
	pinned, err := pinWorkerSocket(base, m.binding.Service, "wd-provider")
	if err != nil {
		return err
	}
	defer pinned.file.Close()
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(base, "wd-provider.sock"), Net: "unix"})
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return err
	}
	var peer *unix.Ucred
	var nativeErr error
	if err := raw.Control(func(fd uintptr) { peer, nativeErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return err
	}
	if nativeErr != nil || peer == nil || peer.Uid != m.binding.Service.UID || peer.Gid != m.binding.Service.GID || peer.Pid <= 1 {
		return failure(api.CodeUnauthenticated, "usage provider differs from its installed service principal")
	}
	request := struct {
		Schema string `json:"schema"`
		Lease  api.ID `json:"lease_id"`
		UID    uint32 `json:"uid"`
		Active bool   `json:"active"`
	}{"laneboss.wd-enroll.v1", lease.ID, lease.UID, active}
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame, uint32(len(data)))
	copy(frame[4:], data)
	if _, err := connection.Write(frame); err != nil {
		return err
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(header)
	if length == 0 || length > 4096 {
		return failure(api.CodeIntegrity, "usage provider enrollment reply exceeds its bound")
	}
	data = make([]byte, length)
	if _, err := io.ReadFull(connection, data); err != nil {
		return err
	}
	var reply struct {
		Schema string `json:"schema"`
		Lease  api.ID `json:"lease_id"`
		UID    uint32 `json:"uid"`
		Active bool   `json:"active"`
	}
	if err := decodeStrict(data, &reply); err != nil {
		return err
	}
	if reply.Schema != "laneboss.wd-enrolled.v1" || reply.Lease != lease.ID || reply.UID != lease.UID || reply.Active != active {
		return failure(api.CodeIntegrity, "usage provider changed its actual allocated principal")
	}
	return nil
}
