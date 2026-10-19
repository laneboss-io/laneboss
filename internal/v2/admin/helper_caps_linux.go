//go:build linux

package admin

import (
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
	linuxunit "laneboss.io/laneboss/packaging/v2/linux"
)

func readHelperUIDs() ([3]uint32, error) {
	var ids [3]uint32
	_, _, errno := unix.RawSyscall(unix.SYS_GETRESUID, uintptr(unsafe.Pointer(&ids[0])), uintptr(unsafe.Pointer(&ids[1])), uintptr(unsafe.Pointer(&ids[2])))
	runtime.KeepAlive(&ids)
	if errno != 0 {
		return [3]uint32{}, errno
	}
	return ids, nil
}

// This is the Linux capability name/number namespace, not a helper policy list.
// The intended subset comes only from the embedded installer unit below.
var linuxCapabilityNumbers = map[string]uint{
	"CAP_CHOWN":              unix.CAP_CHOWN,
	"CAP_DAC_OVERRIDE":       unix.CAP_DAC_OVERRIDE,
	"CAP_DAC_READ_SEARCH":    unix.CAP_DAC_READ_SEARCH,
	"CAP_FOWNER":             unix.CAP_FOWNER,
	"CAP_FSETID":             unix.CAP_FSETID,
	"CAP_KILL":               unix.CAP_KILL,
	"CAP_SETGID":             unix.CAP_SETGID,
	"CAP_SETUID":             unix.CAP_SETUID,
	"CAP_SETPCAP":            unix.CAP_SETPCAP,
	"CAP_LINUX_IMMUTABLE":    unix.CAP_LINUX_IMMUTABLE,
	"CAP_NET_BIND_SERVICE":   unix.CAP_NET_BIND_SERVICE,
	"CAP_NET_BROADCAST":      unix.CAP_NET_BROADCAST,
	"CAP_NET_ADMIN":          unix.CAP_NET_ADMIN,
	"CAP_NET_RAW":            unix.CAP_NET_RAW,
	"CAP_IPC_LOCK":           unix.CAP_IPC_LOCK,
	"CAP_IPC_OWNER":          unix.CAP_IPC_OWNER,
	"CAP_SYS_MODULE":         unix.CAP_SYS_MODULE,
	"CAP_SYS_RAWIO":          unix.CAP_SYS_RAWIO,
	"CAP_SYS_CHROOT":         unix.CAP_SYS_CHROOT,
	"CAP_SYS_PTRACE":         unix.CAP_SYS_PTRACE,
	"CAP_SYS_PACCT":          unix.CAP_SYS_PACCT,
	"CAP_SYS_ADMIN":          unix.CAP_SYS_ADMIN,
	"CAP_SYS_BOOT":           unix.CAP_SYS_BOOT,
	"CAP_SYS_NICE":           unix.CAP_SYS_NICE,
	"CAP_SYS_RESOURCE":       unix.CAP_SYS_RESOURCE,
	"CAP_SYS_TIME":           unix.CAP_SYS_TIME,
	"CAP_SYS_TTY_CONFIG":     unix.CAP_SYS_TTY_CONFIG,
	"CAP_MKNOD":              unix.CAP_MKNOD,
	"CAP_LEASE":              unix.CAP_LEASE,
	"CAP_AUDIT_WRITE":        unix.CAP_AUDIT_WRITE,
	"CAP_AUDIT_CONTROL":      unix.CAP_AUDIT_CONTROL,
	"CAP_SETFCAP":            unix.CAP_SETFCAP,
	"CAP_MAC_OVERRIDE":       unix.CAP_MAC_OVERRIDE,
	"CAP_MAC_ADMIN":          unix.CAP_MAC_ADMIN,
	"CAP_SYSLOG":             unix.CAP_SYSLOG,
	"CAP_WAKE_ALARM":         unix.CAP_WAKE_ALARM,
	"CAP_BLOCK_SUSPEND":      unix.CAP_BLOCK_SUSPEND,
	"CAP_AUDIT_READ":         unix.CAP_AUDIT_READ,
	"CAP_PERFMON":            unix.CAP_PERFMON,
	"CAP_BPF":                unix.CAP_BPF,
	"CAP_CHECKPOINT_RESTORE": unix.CAP_CHECKPOINT_RESTORE,
}

func intendedHelperCapabilities() (uint64, error) {
	return helperCapabilitySet(linuxunit.HelperTemplate())
}

func helperCapabilitySet(template string) (uint64, error) {
	var result uint64
	sets := 0
	service := false
	for _, line := range strings.Split(template, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			service = line == "[Service]"
		}
		name, value, found := strings.Cut(line, "=")
		if !service || !found || strings.TrimSpace(name) != "CapabilityBoundingSet" {
			continue
		}
		sets++
		seen := map[string]bool{}
		for _, name := range strings.Fields(value) {
			number, known := linuxCapabilityNumbers[name]
			if !known || seen[name] {
				return 0, unix.EINVAL
			}
			seen[name] = true
			result |= uint64(1) << number
		}
	}
	if sets != 1 || result == 0 {
		return 0, unix.EINVAL
	}
	return result, nil
}
