package identityd

import "golang.org/x/sys/unix"

// XUCRED_VERSION in Darwin's sys/ucred.h. x/sys does not export this constant.
const xucredVersion = 0

// LOCAL_PEERPID/start is a diagnostic snapshot, not a lifetime binding. Until
// XNU LOCAL_PEERTOKEN/pidversion has been verified, mutations fail closed here.
type darwinLifetime struct{ peer Peer }

func (p *darwinLifetime) check() error {
	current, err := nativeProcess(p.peer.PID)
	if err != nil || current.UID != p.peer.UID || current.GID != p.peer.GID {
		return refuse("the peer's kernel process identity cannot be read\nInstead: reconnect from a live session.")
	}
	return nil
}

func (*darwinLifetime) mutationAllowed() error {
	return refuse("identity service registration is unsupported on macOS\nInstead: use a supported Linux identity service deployment; without a service, macOS retains legacy open registration with its notice.")
}

func (*darwinLifetime) close() error { return nil }
func (*darwinLifetime) mode() string { return "snapshot-readonly" }

func peerCredentials(fd int) (Peer, peerLifetime, error) {
	credential, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return Peer{}, nil, err
	}
	pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	if err != nil {
		return Peer{}, nil, err
	}
	if credential.Version != xucredVersion || credential.Ngroups < 1 || credential.Ngroups > int16(len(credential.Groups)) || pid <= 1 {
		return Peer{}, nil, processUnavailable()
	}
	peer := Peer{PID: pid, UID: credential.Uid, GID: credential.Groups[0]}
	return peer, &darwinLifetime{peer: peer}, nil
}
