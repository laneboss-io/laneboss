package report

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
)

var terminalTarget = regexp.MustCompile(`^(human|(?:supervisor|instance):[A-Za-z0-9][A-Za-z0-9._-]{0,63})$`)
var reportIdentity = regexp.MustCompile(`^report-[0-9a-f]{32}$`)

type terminalTicket struct {
	PID    int
	Start  string
	Target string
}

func (t terminalTicket) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"target":  t.Target,
		"process": map[string]any{"pid": t.PID, "start": t.Start},
	})
}

func (t *terminalTicket) UnmarshalJSON(data []byte) error {
	var record struct {
		Target  string `json:"target"`
		Process struct {
			PID   int    `json:"pid"`
			Start string `json:"start"`
		} `json:"process"`
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return err
	}
	t.PID, t.Start, t.Target = record.Process.PID, record.Process.Start, record.Target
	return nil
}

func processStart(pid int) (string, error) { return caller.ProcessStart(pid) }

func terminalRoot(state string, create bool) (*os.Root, error) {
	root, err := os.OpenRoot(state)
	if err != nil {
		if !create && errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot open terminal state root")
	}
	defer root.Close()
	if err = checkComponents(root, "reports/terminals/.entry", create); err != nil {
		return nil, err
	}
	terminals, err := root.OpenRoot("reports/terminals")
	if !create && errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot open terminal channel directory")
	}
	return terminals, nil
}

func readTicket(root *os.Root, target string) (*terminalTicket, error) {
	if !terminalTarget.MatchString(target) {
		return nil, fmt.Errorf("invalid terminal target")
	}
	file, err := root.OpenFile(target+".json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read terminal process ticket")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("terminal process ticket must be a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() || stat.Nlink != 1 || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("terminal process ticket must be private and owned by this user")
	}
	var ticket terminalTicket
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 || json.Unmarshal(data, &ticket) != nil || ticket.Target != target || ticket.Start == "" {
		return nil, fmt.Errorf("invalid terminal process ticket")
	}
	start, err := processStart(ticket.PID)
	if err != nil {
		return nil, err
	}
	if start == "" || start != ticket.Start {
		return nil, nil
	}
	pipe, err := root.Lstat(target + ".fifo")
	if err != nil || pipe.Mode()&os.ModeNamedPipe == 0 || pipe.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("terminal channel requires its recorded FIFO")
	}
	pipeStat, ok := pipe.Sys().(*syscall.Stat_t)
	if !ok || int(pipeStat.Uid) != os.Getuid() || pipe.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("terminal FIFO must be private and owned by this user")
	}
	return &ticket, nil
}

func terminalLive(state, target string) (bool, error) {
	if !terminalTarget.MatchString(target) {
		return false, fmt.Errorf("invalid terminal target")
	}
	root, err := terminalRoot(state, false)
	if err != nil || root == nil {
		return false, err
	}
	defer root.Close()
	ticket, err := readTicket(root, target)
	return ticket != nil, err
}

// A small FIFO notification names a kept report. Keeping the full UTF-8 text
// separately ensures that a 4000-character report fits one atomic,
// non-blocking pipe write even when it contains multibyte characters.
func sendTerminal(state, target string, payload eventstore.Object) error {
	root, err := terminalRoot(state, false)
	if err != nil {
		return err
	}
	if root == nil {
		return fmt.Errorf("the terminal watcher is no longer live")
	}
	defer root.Close()
	ticket, err := readTicket(root, target)
	if err != nil {
		return err
	}
	if ticket == nil {
		return fmt.Errorf("the terminal watcher is no longer live")
	}
	id := text(payload["report_id"])
	if !reportIdentity.MatchString(id) {
		return fmt.Errorf("invalid terminal report identity")
	}
	name := id + ".json"
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("cannot keep the terminal report")
	}
	data, err := json.Marshal(payload)
	if err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return fmt.Errorf("cannot keep the complete terminal report")
	}
	pipe, err := root.OpenFile(target+".fifo", os.O_WRONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("the terminal watcher is unavailable")
	}
	defer pipe.Close()
	info, err := pipe.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return fmt.Errorf("the terminal channel is not a FIFO")
	}
	// Use the kernel write directly: os.File.Write may wait on its poller when
	// the FIFO is full, which would violate the non-blocking channel contract.
	line := []byte(id + "\n")
	n, err := syscall.Write(int(pipe.Fd()), line)
	if err != nil || n != len(line) {
		return fmt.Errorf("the terminal FIFO is full or the watcher has gone away")
	}
	return nil
}

func watch(c *config.Configuration, store *eventstore.Configuration, from caller.Principal, target string, stdout, stderr io.Writer) int {
	if !terminalTarget.MatchString(target) || from.ID == "" || from.ID != "human" && from.ID != target {
		fmt.Fprintln(stderr, "refused: report watch --as must be the resolved principal, or be opened by a human\nInstead: report up with laneboss report.")
		return 2
	}
	if strings.HasPrefix(from.ID, "lane:") {
		fmt.Fprintln(stderr, "refused: lanes receive reports through their mail queue")
		return 2
	}
	d, err := store.OpenDirectory(true)
	if err != nil {
		fmt.Fprintln(stderr, "report watch: "+err.Error())
		return 3
	}
	d.Close()
	root, err := terminalRoot(c.StateDir, true)
	if err != nil {
		fmt.Fprintln(stderr, "report watch: "+err.Error())
		return 3
	}
	defer root.Close()
	lock, err := root.OpenFile(target+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		fmt.Fprintln(stderr, "report watch: cannot open watcher lock")
		return 3
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		fmt.Fprintln(stderr, "refused: a watcher for this target is already live")
		return 2
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	start, err := processStart(os.Getpid())
	if err != nil || start == "" {
		fmt.Fprintln(stderr, "report watch: cannot record process identity")
		return 3
	}
	dir, err := root.Open(".")
	if err != nil {
		fmt.Fprintln(stderr, "report watch: cannot pin terminal directory")
		return 3
	}
	defer dir.Close()
	fifo := target + ".fifo"
	if info, err := root.Lstat(fifo); err == nil {
		if info.Mode()&os.ModeNamedPipe == 0 || info.Mode()&os.ModeSymlink != 0 {
			fmt.Fprintln(stderr, "report watch: existing channel is not a FIFO")
			return 3
		}
		if err = root.Remove(fifo); err != nil {
			fmt.Fprintln(stderr, "report watch: cannot collect stale FIFO")
			return 3
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stderr, "report watch: cannot inspect FIFO")
		return 3
	}
	if err = createFIFO(root, dir, fifo); err != nil {
		fmt.Fprintln(stderr, "report watch: cannot create FIFO")
		return 3
	}
	defer root.Remove(fifo)
	pipe, err := root.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		fmt.Fprintln(stderr, "report watch: cannot open FIFO")
		return 3
	}
	defer pipe.Close()
	ticketName := target + ".json"
	if info, err := root.Lstat(ticketName); err == nil {
		if !info.Mode().IsRegular() {
			fmt.Fprintln(stderr, "report watch: existing process ticket is not a regular file")
			return 3
		}
		if err = root.Remove(ticketName); err != nil {
			fmt.Fprintln(stderr, "report watch: cannot collect stale process ticket")
			return 3
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stderr, "report watch: cannot inspect process ticket")
		return 3
	}
	ticket, err := root.OpenFile(ticketName, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		fmt.Fprintln(stderr, "report watch: cannot write process ticket")
		return 3
	}
	err = json.NewEncoder(ticket).Encode(terminalTicket{PID: os.Getpid(), Start: start, Target: target})
	if err == nil {
		err = ticket.Sync()
	}
	closeErr := ticket.Close()
	if err != nil || closeErr != nil {
		fmt.Fprintln(stderr, "report watch: cannot sync process ticket")
		return 3
	}
	defer root.Remove(ticketName)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	lines := make(chan string)
	readErrors := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(pipe)
		scanner.Buffer(make([]byte, 128), 128)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
		readErrors <- scanner.Err()
	}()
	if _, err = fmt.Fprintln(stdout, "report watch: ready for "+target); err != nil {
		fmt.Fprintln(stderr, "report watch: cannot write readiness")
		return 3
	}
	for {
		select {
		case <-ctx.Done():
			return 0
		case err := <-readErrors:
			if err != nil {
				fmt.Fprintln(stderr, "report watch: cannot read FIFO")
				return 3
			}
			return 0
		case id := <-lines:
			if !reportIdentity.MatchString(id) {
				fmt.Fprintln(stderr, "report watch: invalid FIFO notification")
				return 3
			}
			file, err := root.OpenFile(id+".json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
			if err != nil {
				fmt.Fprintln(stderr, "report watch: terminal report is missing")
				return 3
			}
			data, readErr := io.ReadAll(io.LimitReader(file, 65537))
			file.Close()
			var payload eventstore.Object
			if readErr != nil || len(data) > 65536 || json.Unmarshal(data, &payload) != nil || payload["to"] != target || payload["report_id"] != id {
				fmt.Fprintln(stderr, "report watch: terminal report is invalid")
				return 3
			}
			if err = json.NewEncoder(stdout).Encode(payload); err != nil {
				fmt.Fprintln(stderr, "report watch: cannot write terminal report")
				return 3
			}
			if err = root.Remove(id + ".json"); err != nil {
				fmt.Fprintln(stderr, "report watch: cannot collect delivered terminal report")
				return 3
			}
		}
	}
}
