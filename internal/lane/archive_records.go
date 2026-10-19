package lane

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/faults"
)

func archiveReportPayload(source string, data []byte) (object, error) {
	if faults.Get("archive-report-assignment-refusal").Point != "" && regexp.MustCompile(`(?m)^\s*[A-Za-z_][A-Za-z0-9_.-]*\s*=\s*\S`).Match(data) {
		if err := faults.Reach("archive-report-assignment-refusal"); err != nil {
			return nil, err
		}
		return nil, refuse("record contains settings values; keep only the source name and hash with --private")
	}
	return eventstore.RecordPayload("lane-report", source, data, eventstore.RecordSettings(source, data))
}

// Absence is distinct from an unreadable or invalid report. Only automatic
// clean may replace this observation with an explicit archival note.
type noRunReport struct {
	run        int
	start, end int64
	hash       string
	hasSpan    bool
}

func (n *noRunReport) Error() string {
	if n.hasSpan {
		return "the latest run report is empty; no report was invented"
	}
	return "the lane has no report or latest run record"
}

func (n *noRunReport) payload(lane string) (object, error) {
	text := fmt.Sprintf("# Latest run report status\n\nLane %s. Run %d.\n", lane, n.run)
	if n.hasSpan {
		text += fmt.Sprintf("The latest run produced no report.\nRead output.log span %d:%d (%d bytes).\nSpan sha256 %s.\n", n.start, n.end, n.end-n.start, n.hash)
	} else {
		text += "No latest run record is available.\nThe log span was not read; report output is unknown.\n"
	}
	source := fmt.Sprintf("archive:no-report:%s:run:%d", lane, n.run)
	return eventstore.RecordPayload("lane-report", source, []byte(text), false)
}

// Match history ingest's report provenance: the latest run record, not a guessed
// tail of the shared log. The raw record is retained for later history ingests.
func (s *session) archiveRunReport(lane string, root *os.Root) (object, error) {
	records, err := s.everyRecord(lane)
	if err != nil {
		return nil, s.archiveReportRemedy(lane, err)
	}
	row, err := s.known(lane)
	if err != nil {
		return nil, err
	}
	run := integer(row["run"])
	started, err := s.last(lane, "lane.started")
	if err != nil {
		return nil, err
	}
	launch := str(obj(started["payload"])["launch"])
	var latest object
	for _, record := range records {
		if str(record["launch"]) == launch {
			if integer(record["run"]) != run {
				return nil, s.archiveReportRemedy(lane, refuse("the latest run record does not match the current run"))
			}
			latest = record
		}
	}
	if latest == nil {
		return nil, &noRunReport{run: run}
	}
	span := obj(latest["log"])
	if !whole(span["start"], 0, 1<<62) || !whole(span["end"], 0, 1<<62) || number(span["end"]) < number(span["start"]) || number(span["end"])-number(span["start"]) > 512*1024 {
		return nil, s.archiveReportRemedy(lane, refuse("the latest run report has an invalid range or exceeds the 512 KiB record limit"))
	}
	info, err := root.Lstat("output.log")
	if err != nil || !info.Mode().IsRegular() {
		return nil, s.archiveReportRemedy(lane, refuse("the latest run report is missing or not a regular file"))
	}
	log, err := childOpen(root, "output.log", os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, s.archiveReportRemedy(lane, refuse("the latest run report cannot be read from output.log"))
	}
	defer log.Close()
	info, err = log.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, s.archiveReportRemedy(lane, refuse("the latest run report is not a regular file"))
	}
	start, end := int64(number(span["start"])), int64(number(span["end"]))
	if end > info.Size() {
		return nil, s.archiveReportRemedy(lane, refuse("the latest run report has fewer bytes than its recorded range"))
	}
	data := make([]byte, end-start)
	n, err := log.ReadAt(data, start)
	if err != nil && err != io.EOF || int64(n) != end-start {
		return nil, s.archiveReportRemedy(lane, refuse("the latest run report has fewer bytes than its recorded range"))
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, &noRunReport{run: run, start: start, end: end, hash: digest(data), hasSpan: true}
	}
	payload, err := archiveReportPayload(fmt.Sprintf("%s#%d:%d", s.lanePath(lane, "output.log"), start, end), data)
	if err != nil {
		return nil, s.archiveReportRemedy(lane, err)
	}
	return payload, nil
}

func (s *session) archiveReportRemedy(lane string, cause error) error {
	if p, ok := cause.(*problem); ok && p.code == 3 {
		return cause
	}
	return refuse("lane report: write a reviewed, credential-free lanes/%s/report.md under this configuration's state directory to override the stored report or run span; %s", lane, safeMessage(cause.Error()))
}

// Match only the already enumerated lane files. Unlike a discovery glob, this
// neither traverses a runner's home nor truncates a list of matching records.
func archiveRecordMatch(pattern, path string) bool {
	parts := strings.Split(filepath.ToSlash(filepath.Clean(pattern)), "/")
	names := strings.Split(filepath.ToSlash(filepath.Clean(path)), "/")
	seen, answers := map[[2]int]bool{}, map[[2]int]bool{}
	var matchParts func(int, int) bool
	matchParts = func(i, j int) bool {
		key := [2]int{i, j}
		if seen[key] {
			return answers[key]
		}
		seen[key] = true
		var answer bool
		if i == len(parts) {
			answer = j == len(names)
		} else if parts[i] == "**" {
			answer = matchParts(i+1, j) || j < len(names) && matchParts(i, j+1)
		} else if j < len(names) {
			yes, err := filepath.Match(parts[i], names[j])
			answer = err == nil && yes && matchParts(i+1, j+1)
		}
		answers[key] = answer
		return answer
	}
	return matchParts(0, 0)
}

func (s *session) archiveRawRecords(lane string, entries []archiveEntry) (map[string]bool, error) {
	kept := map[string]bool{s.lanePath(lane, "output.log"): true}
	runs, err := s.scanRuns(lane)
	if err != nil {
		return nil, err
	}
	for _, run := range runs {
		runner := obj(obj(s.c.data["runners"])[run.runner])
		uncertain := runner == nil
		for _, record := range list(runner["records"]) {
			for _, template := range stringsOf(obj(record)["paths"]) {
				pattern, reason := expandRecord(template, run)
				if reason != "" {
					uncertain = true
					continue
				}
				for _, entry := range entries {
					if archiveRecordMatch(pattern, entry.source) {
						kept[entry.source] = true
					}
				}
			}
		}
		// If a historical template can no longer be expanded, keeping diagnostic
		// logs is preferable to deleting an unrecognised raw runner record.
		if uncertain {
			for _, entry := range entries {
				kept[entry.source] = true
			}
		}
	}
	return kept, nil
}

// Called under the lifecycle lock, including for a manual archive invocation.
func (s *session) alreadyArchived(lane string) (bool, error) {
	row, err := s.known(lane)
	if err != nil || !flag(row["cleaned"]) {
		return false, err
	}
	completed, err := s.last(lane, "archive.completed")
	if err != nil || completed == nil {
		return false, err
	}
	started, err := s.last(lane, "lane.started")
	if err != nil {
		return false, err
	}
	if started != nil && integer(completed["seq"]) <= integer(started["seq"]) {
		return false, nil
	}
	entries, err := archiveLogs(s.lanePath(lane))
	if err != nil {
		return false, err
	}
	kept, err := s.archiveRawRecords(lane, entries)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Path, ".log") && !kept[entry.source] {
			return false, nil
		}
	}
	return true, nil
}
