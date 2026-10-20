//go:build linux

package admin

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

type fileLeaseStore struct {
	root    *os.Root
	owner   uint32 // Runtime construction fixes this to root; tests use their own identity.
	pending uint64
	shapes  map[string][32]byte
}

var pendingName = regexp.MustCompile(`^pending-[a-f0-9]{32}$`)

func (s *fileLeaseStore) Pending() uint64 { return s.pending }

func (s *fileLeaseStore) Records() ([]leaseRecord, error) {
	records, issues, err := s.Inventory()
	if err != nil {
		return nil, err
	}
	if len(issues) != 0 {
		return nil, errors.Join(issues...)
	}
	return records, nil
}

func (s *fileLeaseStore) Inventory() ([]leaseRecord, []error, error) {
	directory, err := s.root.Open(".")
	if err != nil {
		return nil, nil, failure(api.CodeIntegrity, "cannot open helper lease directory")
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return nil, nil, failure(api.CodeIntegrity, "cannot enumerate helper lease records")
	}
	result := []leaseRecord{}
	validated := make(map[string][32]byte, len(entries))
	var issues []error
	s.pending = 0
	for _, entry := range entries {
		if entry.Name() == "proofs" {
			if err := checkIsolationReservations(s.root, s.owner); err != nil {
				return nil, nil, err
			}
			continue
		}
		if entry.Name() == "spools" || entry.Name() == "sources" || entry.Name() == "jobs" || entry.Name() == "workspaces" || entry.Name() == "claudock" {
			parent, err := s.root.Open(".")
			if err != nil {
				return nil, nil, failure(api.CodeIntegrity, "cannot pin helper storage parent")
			}
			file, err := openStorageDirectory(parent, entry.Name())
			parent.Close()
			if err != nil {
				return nil, nil, failure(api.CodeIntegrity, "cannot pin private capture spool parent")
			}
			var stat unix.Stat_t
			if entry.Name() == "workspaces" || entry.Name() == "claudock" {
				if err := dataNoAttributes(file); err != nil {
					file.Close()
					return nil, nil, err
				}
			}
			statErr, closeErr := unix.Fstat(int(file.Fd()), &stat), file.Close()
			if statErr != nil || closeErr != nil || stat.Uid != s.owner || stat.Mode&07777 != 0700 || (entry.Name() == "workspaces" || entry.Name() == "claudock") && s.owner == 0 && stat.Gid != 0 {
				return nil, nil, failure(api.CodeIntegrity, "unsafe capture spool parent")
			}
			continue
		}
		if entry.Name() == "lock" {
			continue
		}
		if pendingName.MatchString(entry.Name()) {
			f, err := s.root.OpenFile(entry.Name(), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
			if err != nil {
				return nil, nil, failure(api.CodeIntegrity, "cannot pin unpublished helper state")
			}
			var info unix.Stat_t
			statErr := unix.Fstat(int(f.Fd()), &info)
			closeErr := f.Close()
			if statErr != nil || closeErr != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != s.owner ||
				info.Mode&0777 != 0600 || info.Nlink != 1 || info.Size > api.MaxFrameBytes {
				return nil, nil, failure(api.CodeIntegrity, "unsafe unpublished helper state")
			}
			// It was never published. Keep the bytes for diagnosis and continue
			// using the last atomic record; never interpret a partial JSON file.
			s.pending++
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".json") || !validID(api.ID(strings.TrimSuffix(entry.Name(), ".json"))) {
			return nil, nil, failure(api.CodeIntegrity, "unrecognized helper state object; retain partial state for recovery")
		}
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			issues = append(issues, failure(api.CodeIntegrity, fmt.Sprintf("retained linked or non-file helper record %s", entry.Name())))
			continue
		}
		f, err := s.root.OpenFile(entry.Name(), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			issues = append(issues, failure(api.CodeIntegrity, fmt.Sprintf("retained unreadable helper record %s", entry.Name())))
			continue
		}
		var stat unix.Stat_t
		statErr := unix.Fstat(int(f.Fd()), &stat)
		data, readErr := io.ReadAll(io.LimitReader(f, api.MaxFrameBytes+1))
		closeErr := f.Close()
		if statErr != nil || readErr != nil || closeErr != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
			stat.Uid != s.owner || stat.Mode&0777 != 0600 || stat.Nlink != 1 || stat.Size > api.MaxFrameBytes || len(data) > api.MaxFrameBytes {
			issues = append(issues, failure(api.CodeIntegrity, fmt.Sprintf("retained unsafe helper record %s", entry.Name())))
			continue
		}
		var record leaseRecord
		digest := sha256.Sum256(data)
		decode := decodeStrict
		if prior, ok := s.shapes[entry.Name()]; ok && prior == digest {
			// Only the strict byte/shape check is reusable. Read and protect
			// every file as before, and decode a fresh object so no mutable
			// pointer aliases another read. Changed bytes take the full strict
			// path; manager validation and native observations always run.
			decode = json.Unmarshal
		}
		if err := decode(data, &record); err != nil {
			issues = append(issues, failure(api.CodeIntegrity, fmt.Sprintf("retained malformed helper record %s", entry.Name())))
			continue
		}
		if entry.Name() != string(record.Lease.ID)+".json" {
			issues = append(issues, failure(api.CodeIntegrity, fmt.Sprintf("retained mismatched helper record %s", entry.Name())))
			continue
		}
		validated[entry.Name()] = digest
		result = append(result, record)
	}
	s.shapes = validated
	return result, issues, nil
}

func (s *fileLeaseStore) Save(record leaseRecord) error {
	data, err := json.Marshal(record)
	if err != nil || len(data) > api.MaxFrameBytes || !validID(record.Lease.ID) {
		return failure(api.CodeIntegrity, "cannot encode helper lease record")
	}
	var readback leaseRecord
	if err := decodeStrict(data, &readback); err != nil {
		return failure(api.CodeIntegrity, "helper lease record cannot pass its strict readback")
	}
	id, err := randomID("pending-")
	if err != nil {
		return err
	}
	f, err := s.root.OpenFile(string(id), os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return failure(api.CodeUnavailable, "cannot reserve durable helper lease storage")
	}
	written, writeErr := f.Write(append(data, '\n'))
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || written != len(data)+1 || syncErr != nil || closeErr != nil {
		if err := s.root.Remove(string(id)); err != nil {
			return failure(api.CodeIntegrity, "cannot discard unpublished helper write; preserve its evidence")
		}
		return failure(api.CodeIntegrity, "helper lease write or sync failed; preserve partial state")
	}
	if err := s.root.Rename(string(id), string(record.Lease.ID)+".json"); err != nil {
		return failure(api.CodeIntegrity, "cannot atomically publish helper lease record")
	}
	directory, err := s.root.Open(".")
	if err != nil {
		return failure(api.CodeIntegrity, "cannot sync helper lease directory")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return failure(api.CodeIntegrity, "helper lease directory sync failed")
	}
	return nil
}
