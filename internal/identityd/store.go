package identityd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/caller/records"
	"laneboss.io/laneboss/internal/eventstore"
)

const maxJournalBytes = 256 * 1024 * 1024

// Record is a service journal entry. Payload and Claim never become provenance
// fields. Only register and lane-started entries update the identity projection.
type Record struct {
	Version   int             `json:"laneboss_service"`
	Config    string          `json:"config"`
	Seq       int64           `json:"seq"`
	Time      string          `json:"time"`
	Op        string          `json:"op"`
	Actor     string          `json:"actor"`
	Peer      Peer            `json:"peer"`
	Principal *Principal      `json:"principal,omitempty"`
	Process   *Peer           `json:"process,omitempty"`
	Lane      string          `json:"lane,omitempty"`
	Run       int             `json:"run,omitempty"`
	Type      string          `json:"type,omitempty"`
	Kind      string          `json:"kind,omitempty"`
	To        string          `json:"to,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

type store struct {
	config   string
	root     *os.Root
	lock     *os.File
	journal  *os.File
	seq      int64
	bytes    int64
	failed   bool
	sessions map[int]Record
	lanes    map[string][]Record
}

func openStore(root *os.Root, config string, fileMode os.FileMode) (*store, error) {
	s := &store{config: config, root: root, sessions: map[int]Record{}, lanes: map[string][]Record{}}
	lock, err := privateFile(root, "identityd.lock", 0600)
	if err != nil {
		return nil, err
	}
	s.lock = lock
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, refuse("the service store is already locked\nInstead: use service status or stop the existing service through its service manager.")
	}
	journal, err := privateFile(root, "records.jsonl", fileMode)
	if err != nil {
		lock.Close()
		return nil, err
	}
	s.journal = journal
	if err = s.replay(); err != nil {
		journal.Close()
		lock.Close()
		return nil, err
	}
	if err = journal.Sync(); err == nil {
		var directory *os.File
		directory, err = root.Open(".")
		if err == nil {
			err = errors.Join(directory.Sync(), directory.Close())
		}
	}
	if err != nil {
		journal.Close()
		lock.Close()
		return nil, corrupt("the service store could not be synced")
	}
	return s, nil
}

func (s *store) replay() error {
	info, err := s.journal.Stat()
	if err != nil || info.Size() > maxJournalBytes {
		return corrupt("the service journal is unreadable or exceeds its size limit")
	}
	s.bytes = info.Size()
	reader := bufio.NewReaderSize(s.journal, MaxResponseBytes+1)
	for {
		line, err := reader.ReadSlice('\n')
		if err == io.EOF && len(line) == 0 {
			return nil
		}
		if err != nil || len(line) > MaxResponseBytes {
			return corrupt("the service journal has an incomplete or oversized record")
		}
		if _, err := eventstore.Parse(line, "the service record"); err != nil {
			return corrupt("the service journal has malformed JSON")
		}
		var record Record
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&record); err != nil || !s.validRecord(record) {
			return corrupt("the service journal has an invalid identity record")
		}
		s.project(record)
	}
}

func (s *store) validRecord(record Record) bool {
	if record.Version != Version || record.Config != s.config || record.Seq != s.seq+1 || !records.ValidID(record.Actor) || record.Peer.PID <= 1 || record.Peer.Start == "" {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, record.Time); err != nil {
		return false
	}
	switch record.Op {
	case "register":
		return record.Principal != nil && validSupervisor(*record.Principal) && record.Process != nil && record.Process.PID > 1 && record.Process.Start != "" && record.Process.UID == record.Peer.UID && record.Actor == record.Principal.ID && record.Lane == "" && record.Run == 0 && record.Type == "" && len(record.Payload) == 0
	case "lane-started":
		previous := s.latestLane(record.Lane)
		return record.Principal != nil && validPrincipal(*record.Principal) && record.Principal.ID == "lane:"+record.Lane && record.Principal.Starter == record.Actor && laneName.MatchString(record.Lane) && record.Run == previous.Run+1 && laneOwner(record.Lane, record.Actor, previous) == nil && record.Process != nil && record.Process.PID > 1 && record.Process.Start != "" && record.Process.UID == record.Peer.UID && record.Type == "" && len(record.Payload) == 0
	case "append":
		return record.Principal == nil && record.Process == nil && record.Run == 0 && (record.Type == "event" || record.Type == "report" || record.Type == "send") && len(record.Payload) > 0
	}
	return false
}

func (s *store) project(record Record) {
	s.seq = record.Seq
	switch record.Op {
	case "register":
		s.sessions[record.Process.PID] = record
	case "lane-started":
		s.lanes[record.Lane] = retainRuns(s.lanes[record.Lane], record)
	}
}

func (s *store) latestLane(name string) Record {
	runs := s.lanes[name]
	if len(runs) == 0 {
		return Record{}
	}
	return runs[len(runs)-1]
}

func (s *store) sessionAnchor(line []process) *Peer {
	for _, current := range line {
		if record, ok := s.sessions[current.PID]; ok && samePeer(*record.Process, current.Peer) {
			return record.Process
		}
	}
	return nil
}

func (s *store) resolve(line []process) (Principal, error) {
	principal, _, _, err := s.resolveRoot(line)
	return principal, err
}

func (s *store) resolveRoot(line []process) (Principal, *ProcessRef, *ProcessRef, error) {
	matched := Principal{}
	var root, detachmentRoot *ProcessRef
	nearest, newest, outermost := len(line), 0, -1
	includeRoot := func(index int, peer Peer) {
		if index > outermost {
			outermost = index
			detachmentRoot = &ProcessRef{PID: peer.PID, Start: peer.Start}
		}
	}
	for _, runs := range s.lanes {
		for _, record := range runs {
			for index, current := range line {
				if !samePeer(*record.Process, current.Peer) {
					continue
				}
				includeRoot(index, current.Peer)
				if matched.ID != "" && matched.ID != record.Principal.ID {
					return Principal{}, nil, nil, refuse("the caller matches more than one lane\nInstead: record disjoint lane process roots before issuing this command.")
				}
				if index < nearest || index == nearest && record.Run > newest {
					matched, nearest, newest = *record.Principal, index, record.Run
					root = &ProcessRef{PID: record.Process.PID, Start: record.Process.Start}
				}
			}
		}
	}
	// Lane precedence and the nearest session still select the principal. The
	// detach boundary must also cover outer recorded sessions: after a lane
	// root exits, an adopted orphan must not fall through to one of them.
	for index, current := range line {
		if record, ok := s.sessions[current.PID]; ok && samePeer(*record.Process, current.Peer) {
			includeRoot(index, current.Peer)
			if matched.ID == "" {
				matched = *record.Principal
				root = &ProcessRef{PID: record.Process.PID, Start: record.Process.Start}
			}
		}
	}
	return matched, root, detachmentRoot, nil
}

func (s *store) append(record Record, envelope func(Record) error) (*Record, error) {
	if s.failed {
		return nil, corrupt("the service store is stopped after a write failure")
	}
	record.Version, record.Config, record.Seq = Version, s.config, s.seq+1
	record.Time = time.Now().UTC().Format(time.RFC3339Nano)
	if !s.validRecord(record) {
		return nil, corrupt("the service refused to write an invalid identity record")
	}
	// Check the actual response envelope before any durable side effect.
	if err := envelope(record); err != nil {
		return nil, err
	}
	data, err := json.Marshal(record)
	if err != nil || len(data)+1 > MaxResponseBytes || s.bytes+int64(len(data)+1) > maxJournalBytes {
		return nil, refuse("the service record or journal exceeds its size limit\nInstead: have the service administrator archive the journal before continuing.")
	}
	data = append(data, '\n')
	n, err := s.journal.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = s.journal.Sync()
	}
	if err != nil {
		s.failed = true
		return nil, corrupt("the service record could not be written and synced; further writes are stopped")
	}
	s.bytes += int64(len(data))
	s.project(record)
	return &record, nil
}

func (s *store) close() error {
	return errors.Join(s.journal.Close(), s.lock.Close(), s.root.Close())
}
