//go:build linux

package admin

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) checkWorkspacePointer(r leaseRecord, root *os.File) error {
	var st unix.Stat_t
	err := unix.Fstatat(int(root.Fd()), ".git", &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size < 1 || st.Size > 4096 {
		return failure(api.CodeIntegrity, "archive workspace has an unenrolled Git administration entry")
	}
	target := r.Storage.Binding.Target
	if len(r.LaunchAllocations) > 0 {
		target = r.LaunchAllocations[len(r.LaunchAllocations)-1].Reservation.Target
	}
	e, _, err := m.cleanupEnrollment(target, r.Storage.Binding.WorkspaceID)
	if err != nil {
		return err
	}
	file, err := archFile(root, ".git", false)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := dataNoAttributes(file); err != nil {
		return err
	}
	body, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || string(body) != "gitdir: "+e.GitDir+"\n" {
		return failure(api.CodeIntegrity, "archive workspace Git pointer changed its protected repository")
	}
	return nil
}

// Capture production must actually finish with both pipe EOFs. Saving the
// native wait and closing its descriptors grants no service drain receipt.
func (m *leaseManager) retainArchiveCaptures(ctx context.Context, r *leaseRecord) error {
	for index := range r.Captures {
		entry := &r.Captures[index]
		if entry.Native == nil {
			continue
		}
		n := entry.Native
		if n.Drain != nil && n.Drain.Discharged {
			if err := m.measureDischargedCapture(ctx, *r, *entry); err != nil {
				return err
			}
			continue
		}
		handle := api.ProcessHandle{ID: entry.Binding.ProducerID, Target: entry.Binding.Target, ContainmentID: n.Lease.ContainmentID, Generation: entry.Binding.ProducerGeneration}
		child := leaseRecord{Lease: n.Lease, Request: r.Request, Phase: "active"}
		if n.ArchiveObservation == nil {
			live, ok := m.captures[entry.Binding.ID].(*nativeCapture)
			if !ok {
				return failure(api.CodeContainmentUnknown, "archive capture lost its original pipe and wait owner")
			}
			if err := live.Observe(ctx); err != nil {
				return err
			}
			observation, err := live.gate.Observe(ctx, handle)
			if err != nil {
				return err
			}
			if err := live.cleanExit(observation); err != nil {
				return err
			}
			if err := m.resources.Quiescent(ctx, child); err != nil {
				return err
			}
			zero := uint64(0)
			observation.Survivors = &zero
			if err := dataTerminal(observation, handle); err != nil {
				return err
			}
			file, err := live.spool.Open(".")
			if err != nil {
				return err
			}
			identity, _, identityErr := dataIdentity(file)
			closeErr := file.Close()
			if identityErr != nil {
				return identityErr
			}
			if closeErr != nil {
				return closeErr
			}
			n.ArchiveObservation, n.SpoolIdentity = &observation, identity
			if err := m.save(*r); err != nil {
				return err
			}
		}
		// A reply/close failure after the durable wait must continue closing
		// this same original owner on retry, rather than strand a live entry.
		if owned := m.captures[entry.Binding.ID]; owned != nil {
			live, ok := owned.(*nativeCapture)
			if !ok || capturePID(live) != n.PID || live.binding.ID != entry.Binding.ID {
				return failure(api.CodeContainmentUnknown, "retained capture close selected another native owner")
			}
			if err := live.Close(); err != nil {
				return err
			}
			if err := live.spool.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				return err
			}
			delete(m.captures, entry.Binding.ID)
		}
		if err := dataTerminal(*n.ArchiveObservation, handle); err != nil {
			return err
		}
		if err := m.resources.Quiescent(ctx, child); err != nil {
			return err
		}
		name := filepath.Join(m.binding.statePath(), "spools", string(entry.Binding.ID))
		file, err := archiveRoot(name)
		if err != nil {
			return err
		}
		identity, _, identityErr := dataIdentity(file)
		closeErr := file.Close()
		if identityErr != nil || identity != n.SpoolIdentity {
			return failure(api.CodeIntegrity, "archive capture spool inode changed")
		}
		if closeErr != nil {
			return closeErr
		}
		root, err := openStorageRoot(name)
		if err != nil {
			return err
		}
		_, failureErr := root.Lstat("reconcile-failure")
		if !errors.Is(failureErr, os.ErrNotExist) {
			root.Close()
			return failure(api.CodeContainmentUnknown, "archive capture retained an unresolved reconciliation failure")
		}
		marker, readErr := readSpool(root, entry.Binding)
		closeErr = root.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if marker.Failure != "" || len(marker.Positions) != 2 || !marker.Positions[0].PipeEOF || !marker.Positions[1].PipeEOF {
			return failure(api.CodeContainmentUnknown, "archive capture EOF or retained ranges are incomplete")
		}
	}
	return nil
}
