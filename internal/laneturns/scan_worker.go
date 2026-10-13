package laneturns

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

type scanProcess struct {
	command              *exec.Cmd
	input                io.WriteCloser
	answered             chan struct{}
	exited               chan error
	readerDone           chan struct{}
	answerOnce, stopOnce sync.Once
	mutex                sync.Mutex
}

func startScanProcess(s *laneSession, lane string, run int, offset int64, recorder *turnRecorder, watch io.Writer) (*scanProcess, error) {
	binary, err := os.Executable()
	if err != nil {
		return nil, err
	}
	command := exec.Command(binary, "turn", "__turn_scan")
	input, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		input.Close()
		return nil, err
	}
	command.Stderr = watch
	if err = command.Start(); err != nil {
		input.Close()
		output.Close()
		return nil, err
	}
	process := &scanProcess{command: command, input: input, answered: make(chan struct{}), exited: make(chan error, 1), readerDone: make(chan struct{})}
	go func() {
		defer close(process.readerDone)
		reader := bufio.NewReader(output)
		for {
			line, err := reader.ReadBytes('\n')
			if len(line) > 0 {
				value, decodeErr := decodeJSON(line)
				if decodeErr == nil {
					if event := obj(value["event"]); event != nil {
						kind := str(event["kind"])
						p := obj(event["payload"])
						if kind == "lane.refusal" || kind == "lane.workaround_suspected" {
							e, eErr := envelope(kind, lane, "laneboss", p)
							if eErr == nil {
								e["occurred_at"] = event["at"]
								recorder.put(e)
							}
						}
					} else if flag(value["done"]) {
						process.answerOnce.Do(func() { close(process.answered) })
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() { <-process.readerDone; process.exited <- command.Wait() }()
	if err = process.send(object{"config": s.c.name, "lane": lane, "run": run, "log_start": offset}); err != nil {
		process.stop()
		return nil, err
	}
	return process, nil
}
func (p *scanProcess) pid() int {
	if p == nil {
		return 0
	}
	return p.command.Process.Pid
}
func (p *scanProcess) send(value object) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	encoder := json.NewEncoder(p.input)
	return encoder.Encode(value)
}
func (p *scanProcess) stop() {
	if p == nil {
		return
	}
	p.stopOnce.Do(func() {
		p.input.Close()
		select {
		case <-p.exited:
		case <-time.After(time.Second):
			p.command.Process.Kill()
			select {
			case <-p.exited:
			case <-time.After(time.Second):
			}
		}
		select {
		case <-p.readerDone:
		case <-time.After(time.Second):
		}
	})
}
func (p *scanProcess) finish(at string, end int64) bool {
	if p == nil {
		return true
	}
	sent := p.send(object{"final": true, "ended_at": at, "log_end": end}) == nil
	answered := false
	if sent {
		select {
		case <-p.answered:
			answered = true
		case <-p.readerDone:
			select {
			case <-p.answered:
				answered = true
			default:
			}
		case <-time.After(5 * time.Second):
		}
	}
	p.stop()
	return answered
}
func scanWorker(stdin io.Reader, stdout, stderr io.Writer) int {
	reader := bufio.NewReader(stdin)
	first, err := reader.ReadBytes('\n')
	if err != nil {
		return reportError(stderr, refused("the refusal scanner received no job"))
	}
	job, err := decodeJSON(first)
	if err != nil || !exactKeys(job, "config lane run log_start") || !namePattern.MatchString(str(job["config"])) || !lanePattern.MatchString(str(job["lane"])) || !boundedInteger(job["run"], 1, 1000000) || !boundedInteger(job["log_start"], 0, 1<<62) {
		return reportError(stderr, refused("the refusal scanner's job is malformed"))
	}
	c, err := loadConfig(str(job["config"]))
	if err != nil {
		return reportError(stderr, err)
	}
	s, err := openSession(c, false)
	if err != nil {
		return reportError(stderr, err)
	}
	defer s.close()
	scan, err := newLaneScan(s, str(job["lane"]), integer(job["run"]), int64(number(job["log_start"])), func(kind string, p object, at any) error {
		return printJSON(stdout, object{"event": object{"kind": kind, "payload": p, "at": at}})
	})
	if err != nil {
		return reportError(stderr, err)
	}
	type commandLine struct {
		value object
		err   error
	}
	commands := make(chan commandLine, 1)
	go func() {
		for {
			line, err := reader.ReadBytes('\n')
			var value object
			if len(line) > 0 {
				value, err = decodeJSON(line)
			}
			commands <- commandLine{value, err}
			if err != nil {
				return
			}
		}
	}()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	saved := time.Now()
	completed := false
	defer func() {
		if !completed {
			if err := scan.save(false); err != nil {
				fmt.Fprintf(stderr, "%s refusal coverage could not be saved: %s\n", nowStamp(), safeDetail(err))
			}
		}
	}()
	for {
		if err = scan.poll(false); err != nil {
			return reportError(stderr, err)
		}
		if time.Since(saved) >= 5*time.Second {
			if err = scan.save(false); err != nil {
				return reportError(stderr, err)
			}
			saved = time.Now()
		}
		select {
		case command := <-commands:
			if command.err == io.EOF {
				return 0
			}
			if command.err != nil {
				return reportError(stderr, command.err)
			}
			if flag(command.value["final"]) {
				current := scan.runs[len(scan.runs)-1]
				current.end, _ = moment(command.value["ended_at"])
				current.ended = true
				if isWhole(command.value["log_end"]) {
					current.logEnd = int64(number(command.value["log_end"]))
					for _, record := range scan.recordOrder {
						if record.format == "text" && record.run == current.run && record.end < 0 {
							record.end = current.logEnd
						}
					}
				}
				if err = scan.poll(true); err != nil {
					return reportError(stderr, err)
				}
				if err = scan.save(true); err != nil {
					return reportError(stderr, err)
				}
				completed = true
				return reportError(stderr, printJSON(stdout, object{"done": true}))
			}
		case <-ticker.C:
		}
	}
}
