//go:build linux

package admin

import (
	"encoding/json"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

type probeReservation struct {
	Schema string
	ID     api.ID
	BootID string
	Lease  api.HelperLease
	Phase  string
}

func proofRead(root *os.Root, name string, owner uint32) ([]byte, error) {
	file, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, failure(api.CodeIntegrity, "cannot read retained isolation proof")
	}
	var st unix.Stat_t
	raw, readErr := io.ReadAll(io.LimitReader(file, api.MaxFrameBytes+1))
	statErr, closeErr := unix.Fstat(int(file.Fd()), &st), file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != owner || st.Mode&07777 != 0600 || st.Nlink != 1 ||
		len(raw) == 0 || len(raw) > api.MaxFrameBytes || int64(len(raw)) != st.Size {
		return nil, failure(api.CodeIntegrity, "retained isolation proof metadata differs")
	}
	return raw, nil
}

func proofWrite(root *os.Root, name string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > api.MaxFrameBytes {
		return failure(api.CodeIntegrity, "cannot encode bounded isolation proof")
	}
	file, err := root.OpenFile("pending", os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return failure(api.CodeIntegrity, "isolation proof has an unfinished publication")
	}
	n, writeErr := file.Write(raw)
	syncErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil || n != len(raw) || syncErr != nil || closeErr != nil {
		return failure(api.CodeIntegrity, "cannot retain exact isolation proof bytes")
	}
	if err := root.Rename("pending", name); err != nil {
		return failure(api.CodeIntegrity, "cannot publish retained isolation proof")
	}
	dir, err := root.Open(".")
	if err != nil {
		return failure(api.CodeIntegrity, "cannot pin isolation proof directory")
	}
	syncErr, closeErr = dir.Sync(), dir.Close()
	if syncErr != nil || closeErr != nil {
		return failure(api.CodeIntegrity, "cannot sync isolation proof directory")
	}
	return nil
}

func proofRoot(parent *os.Root, name string, owner uint32) (*os.Root, error) {
	file, err := parent.OpenFile(name, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, failure(api.CodeIntegrity, "cannot pin private isolation proof directory")
	}
	var st unix.Stat_t
	statErr, closeErr := unix.Fstat(int(file.Fd()), &st), file.Close()
	if statErr != nil || closeErr != nil || st.Uid != owner || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0700 {
		return nil, failure(api.CodeIntegrity, "isolation proof directory has an unsafe owner or mode")
	}
	return parent.OpenRoot(name)
}

// An interrupted probe cannot silently free its pool UID on helper restart.
// The root-owned record and any partial bytes are retained for recovery.
func checkIsolationReservations(parent *os.Root, owner uint32) error {
	root, err := proofRoot(parent, "proofs", owner)
	if err != nil {
		return err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil || closeErr != nil {
		return failure(api.CodeIntegrity, "cannot inventory retained isolation reservations")
	}
	for _, entry := range entries {
		if !validID(api.ID(entry.Name())) {
			return failure(api.CodeIntegrity, "unexpected isolation proof inventory entry")
		}
		item, err := proofRoot(root, entry.Name(), owner)
		if err != nil {
			return err
		}
		raw, readErr := proofRead(item, "reservation.json", owner)
		var held probeReservation
		decodeErr := decodeStrict(raw, &held)
		_, pendingErr := item.Stat("pending")
		closeErr := item.Close()
		if readErr != nil || decodeErr != nil || closeErr != nil || !errors.Is(pendingErr, os.ErrNotExist) || held.Schema != "laneboss.isolation-reservation.v1" ||
			held.ID != api.ID(entry.Name()) || held.Phase != "collected" || held.BootID == "" || held.Lease.UID == 0 || !validID(held.Lease.ID) || !validID(held.Lease.ContainmentID) {
			return failure(api.CodeContainmentUnknown, "retained isolation probe is incomplete; preserve its UID and cgroup for administrator recovery")
		}
	}
	return nil
}
