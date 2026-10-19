package claudock

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
)

var ErrBusy = errors.New("private home or canonical login already has an owner")
var ErrActive = errors.New("credential operation requires verified quiescence")

func busyError() error {
	return fmt.Errorf("%w: %w", &api.Error{Code: api.CodeConflict, Message: "private runner lease is busy",
		Instead: "Wait for the recorded lease owner to finish and verify quiescence.", Retryable: true, Owner: "lb-v2-claudock"}, ErrBusy)
}

func activeError() error {
	return fmt.Errorf("%w: %w", &api.Error{Code: api.CodeConflict, Message: "credential operation lacks quiescence",
		Instead: "Stop the bound run through lifecycle and verify zero survivors before changing its slot.", Owner: "lb-v2-claudock"}, ErrActive)
}

type lease struct{ file *os.File }

// acquire is used only with the protected records root, never a lane-writable
// lock directory. Lock files stay in place across all releases and restarts.
func acquire(root *os.Root, identity string) (*lease, error) {
	hash := sha256.Sum256([]byte(identity))
	name := hex.EncodeToString(hash[:]) + ".lock"
	f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, ownedError(ErrOwnedRead)
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || linked(info) || info.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, ownedError(ErrOwnedType)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			return nil, busyError()
		}
		return nil, failure(api.CodeIntegrity, "private refresh lease could not be acquired")
	}
	return &lease{file: f}, nil
}

func (l *lease) close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	if err != nil {
		return failure(api.CodeIntegrity, "private refresh lease close failed")
	}
	return nil
}
