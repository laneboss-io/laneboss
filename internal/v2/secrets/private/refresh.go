package private

import (
	"errors"
	"io/fs"
	"os"
	"sync"

	"golang.org/x/sys/unix"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// RefreshLease is an actual kernel exclusion lock, independent of journal
// ownership metadata. The empty private file remains as its pinned probe target
// after Close. A new open file description probes the lock, including locks
// retained by another process; a closed Go handle is not evidence of zero locks.
type RefreshLease struct {
	mu       sync.Mutex
	dir      *Directory
	name     string
	file     *os.File
	identity fs.FileInfo
}

func (d *Directory) AcquireRefreshLease(id api.ID) (*RefreshLease, error) {
	if !wire.ID(string(id)) {
		return nil, wire.Error(api.CodeInvalid, "canonical refresh lock requires an exact login")
	}
	if err := d.privacy(); err != nil {
		return nil, err
	}
	name := ".refresh-" + string(id) + ".lock"
	file, err := d.open(name, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || info.Size() != 0 {
		file.Close()
		return nil, wire.Error(api.CodeIntegrity, "canonical refresh lock has unexpected data")
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			return nil, wire.Error(api.CodeIntegrity, "canonical refresh lock close was incomplete")
		}
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, wire.Error(api.CodeConflict, "canonical refresh kernel lease is already held")
		}
		return nil, wire.Error(api.CodeIntegrity, "canonical refresh kernel lease is unavailable")
	}
	return &RefreshLease{dir: d, name: name, file: file, identity: info}, nil
}

func (l *RefreshLease) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.file.Stat(); errors.Is(err, os.ErrClosed) {
		return nil
	} else if err != nil {
		return wire.Error(api.CodeIntegrity, "canonical refresh lease lifetime is unknown")
	}
	// Closing the owning file description releases the kernel lock. Never
	// unlock a still-open handle and call its lifetime closed by a flag.
	if err := l.file.Close(); err != nil {
		return wire.Error(api.CodeIntegrity, "canonical refresh lease close was incomplete")
	}
	return nil
}

func (l *RefreshLease) Check() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	info, err := l.file.Stat()
	if err != nil || !os.SameFile(info, l.identity) {
		return wire.Error(api.CodeConflict, "canonical refresh lease is no longer live")
	}
	held, err := l.probe()
	if err != nil {
		return err
	}
	if !held {
		return wire.Error(api.CodeConflict, "canonical refresh kernel exclusion was lost")
	}
	return nil
}

func (l *RefreshLease) Held() (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.probe()
}

func (l *RefreshLease) probe() (held bool, outErr error) {
	if err := l.dir.privacy(); err != nil {
		return false, err
	}
	file, err := l.dir.open(l.name, os.O_RDWR, 0600)
	if err != nil {
		return false, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			outErr = wire.Error(api.CodeIntegrity, "canonical refresh probe close was incomplete")
		}
	}()
	info, err := file.Stat()
	if err != nil || !os.SameFile(info, l.identity) || info.Size() != 0 {
		return false, wire.Error(api.CodeIntegrity, "canonical refresh probe identity changed")
	}
	err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return true, nil
	}
	if err != nil {
		return false, wire.Error(api.CodeIntegrity, "canonical refresh kernel probe is unavailable")
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		return false, wire.Error(api.CodeIntegrity, "canonical refresh probe unlock was incomplete")
	}
	return false, nil
}
