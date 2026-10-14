// Package hookconfig detects runner hook-load failures without exposing settings.
package hookconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

const ExitCode = 125
const Repair = "hook-config failure: repair hooks.json and re-render the org hooks before resuming"

func CodexKeys(document map[string]any) error {
	for key := range document {
		if key != "hooks" && key != "description" {
			return errors.New("Codex hooks.json has unsupported top-level keys; only hooks and description are accepted")
		}
	}
	if value, exists := document["description"]; exists {
		if _, ok := value.(string); !ok {
			return errors.New("Codex hooks.json description must be a string")
		}
	}
	return nil
}

const parseFailurePrefix = "failed to parse hooks config "
const TrustReviewPrefix = "Non-managed hooks must be reviewed with /hooks before they run."
const maxDiagnosticLine = 65536

type Monitor struct {
	mu            sync.Mutex
	pending       [2][]byte
	discarding    [2]bool
	started       bool
	failed        bool
	path          string
	inspectionErr error
}

type outputWriter struct {
	monitor *Monitor
	output  io.Writer
	stderr  bool
}

// Writer retains raw output while keeping stdout events separate from vendor stderr.
// A fresh monitor belongs to each run; historical logs and tool payloads are not scanned.
func (m *Monitor) Writer(output io.Writer, stderr bool) io.Writer {
	return &outputWriter{monitor: m, output: output, stderr: stderr}
}

func (w *outputWriter) Write(data []byte) (int, error) {
	m := w.monitor
	m.mu.Lock()
	defer m.mu.Unlock()
	n, err := w.output.Write(data)
	if err != nil || n != len(data) {
		m.inspectionErr = errors.New("runner output cannot be checked for hook-load failures")
		if err == nil {
			err = io.ErrShortWrite
		}
	}
	m.consume(data[:n], w.stderr)
	return n, err
}

func (m *Monitor) consume(data []byte, stderr bool) {
	if m.started || m.failed {
		return
	}
	stream := 0
	if stderr {
		stream = 1
	}
	for _, b := range data {
		if b == '\n' {
			if !m.discarding[stream] {
				m.line(strings.TrimSuffix(string(m.pending[stream]), "\r"), stderr)
			}
			m.pending[stream] = m.pending[stream][:0]
			m.discarding[stream] = false
			if m.started || m.failed {
				m.pending = [2][]byte{}
				return
			}
		} else if !m.discarding[stream] {
			if len(m.pending[stream]) == maxDiagnosticLine {
				// Never reinterpret an oversized line's suffix as a startup diagnostic.
				m.pending[stream] = m.pending[stream][:0]
				m.discarding[stream] = true
				m.started = true
			} else {
				m.pending[stream] = append(m.pending[stream], b)
			}
		}
	}
}

func (m *Monitor) line(line string, stderr bool) {
	if m.started || m.failed || line == "" {
		return
	}
	message := ""
	if stderr {
		// Only exact startup diagnostics from the vendor's stderr qualify.
		message = line
	} else {
		var event struct {
			Type string `json:"type"`
			Item struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"item"`
		}
		if json.Unmarshal([]byte(line), &event) != nil {
			m.started = true
			return
		}
		switch event.Type {
		case "thread.started":
			return
		case "item.completed":
			if event.Item.Type != "error" && event.Item.Type != "warning" {
				m.started = true
				return
			}
			message = event.Item.Message
		default:
			// Includes turn.started, agent messages, tool items and deltas.
			m.started = true
			return
		}
	}
	prefix := ""
	for _, known := range []string{parseFailurePrefix, TrustReviewPrefix} {
		if strings.HasPrefix(message, known) {
			prefix = known
			break
		}
	}
	if prefix == "" {
		return
	}
	m.failed = true
	rest := strings.TrimPrefix(message, prefix)
	if end := strings.Index(rest, "hooks.json"); end >= 0 {
		candidate := strings.Trim(rest[:end+len("hooks.json")], " \t\"'`")
		if filepath.IsAbs(candidate) && filepath.Base(candidate) == "hooks.json" && len(candidate) <= 4096 {
			m.path = candidate
		}
	}
}

func (m *Monitor) Poll() (bool, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.failed, m.path, m.inspectionErr
}

func DefaultPath(argv []string, cwd string) string {
	home := os.Getenv("CODEX_HOME")
	for _, word := range argv {
		if strings.HasPrefix(word, "CODEX_HOME=") {
			home = strings.TrimPrefix(word, "CODEX_HOME=")
			break
		}
	}
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		home = filepath.Join(userHome, ".codex")
	}
	if !filepath.IsAbs(home) {
		home = filepath.Join(cwd, home)
	}
	return filepath.Join(home, "hooks.json")
}

type marker struct {
	Run            int    `json:"run"`
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	StopSignalSent bool   `json:"stop_signal_sent"`
}

func readSettings(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Base(path) != "hooks.json" {
		return nil, errors.New(Repair)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2*1024*1024 {
		return nil, errors.New(Repair)
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Nlink != 1 {
		return nil, errors.New(Repair)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New(Repair)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New(Repair)
	}
	data, err := io.ReadAll(io.LimitReader(file, 2*1024*1024+1))
	if err != nil || len(data) > 2*1024*1024 {
		return nil, errors.New(Repair)
	}
	return data, nil
}

func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func Marker(path string, run int, signalSent bool) ([]byte, error) {
	m := marker{Run: run, Path: path, StopSignalSent: signalSent}
	if data, err := readSettings(path); err == nil {
		m.SHA256 = hash(data)
	}
	return json.Marshal(m)
}

func Repaired(data []byte, run int) error {
	var previous marker
	if json.Unmarshal(data, &previous) != nil || previous.Run != run {
		return errors.New(Repair)
	}
	current, err := readSettings(previous.Path)
	if err != nil || hash(current) == previous.SHA256 {
		return errors.New(Repair)
	}
	var document map[string]any
	if json.Unmarshal(current, &document) != nil || CodexKeys(document) != nil {
		return errors.New(Repair)
	}
	hooks, ok := document["hooks"].(map[string]any)
	if !ok {
		return errors.New(Repair)
	}
	rows, ok := hooks["PreToolUse"].([]any)
	if !ok || len(rows) == 0 {
		return errors.New(Repair)
	}
	for _, value := range rows {
		row, ok := value.(map[string]any)
		if !ok {
			return errors.New(Repair)
		}
		commands, ok := row["hooks"].([]any)
		if !ok || len(commands) == 0 {
			return errors.New(Repair)
		}
		for _, value := range commands {
			command, ok := value.(map[string]any)
			if !ok || command["type"] != "command" {
				return errors.New(Repair)
			}
			text, ok := command["command"].(string)
			if !ok || strings.TrimSpace(text) == "" || command["async"] == true {
				return errors.New(Repair)
			}
		}
	}
	return nil
}
