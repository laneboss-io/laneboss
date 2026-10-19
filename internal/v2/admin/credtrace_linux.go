//go:build linux

package admin

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type credWaitFrame struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// The stand-in build records only source locations, never stack arguments,
// process identifiers, absolute paths or request/credential contents. The
// original socket deadline, refusal and connection disposition are unchanged.
func traceCredWait(stage string) func() {
	if !credentialOwnerDetail {
		return func() {}
	}
	done := make(chan struct{})
	timer := time.AfterFunc(2*time.Second, func() {
		defer close(done)
		stack := make([]byte, 1<<20)
		stack = stack[:runtime.Stack(stack, true)]
		frames := credWaitFrames(stack)
		clear(stack)
		_ = json.NewEncoder(os.Stderr).Encode(struct {
			Event string            `json:"event"`
			Stage string            `json:"stage"`
			Waits [][]credWaitFrame `json:"waits"`
		}{"credential_wait", stage, frames})
	})
	return func() {
		if !timer.Stop() {
			<-done
		}
	}
}

func credWaitFrames(stack []byte) [][]credWaitFrame {
	result := [][]credWaitFrame{}
	for _, goroutine := range bytes.Split(stack, []byte("\n\n")) {
		frames := []credWaitFrame{}
		for _, line := range bytes.Split(goroutine, []byte("\n")) {
			// A stack's source line starts with a tab. Function/argument lines
			// are never candidates, even when an argument contains a filename.
			if !bytes.HasPrefix(line, []byte("\t")) {
				continue
			}
			path, _, _ := strings.Cut(string(line[1:]), " +")
			if !strings.Contains(path, "/internal/v2/") {
				continue
			}
			colon := strings.LastIndexByte(path, ':')
			if colon < 0 {
				continue
			}
			file := filepath.Base(path[:colon])
			number, err := strconv.Atoi(path[colon+1:])
			if err != nil || number <= 0 || len(file) >= 40 || !strings.HasSuffix(file, ".go") {
				continue
			}
			frames = append(frames, credWaitFrame{file, number})
		}
		if len(frames) > 0 {
			result = append(result, frames)
		}
	}
	return result
}
