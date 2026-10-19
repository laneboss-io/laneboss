package lifecycle

import (
	"encoding/json"
	"io"
	"os"
	"sync"
)

// allowAndLog: owner R181-R192 (10-18): hardening checks on the lane run-and-finish path (launch, open, running,
// capture, stop, end, collect) are allowed and logged instead of refused, until each is reviewed. Functional checks,
// the blacklist and anything that would expose a credential or another configuration's data still refuse.
func allowAndLog(check string) {
	line, _ := json.Marshal(struct {
		Event string `json:"event"`
		Check string `json:"check"`
	}{"check_allowed", check})
	allowedLog.Lock()
	defer allowedLog.Unlock()
	_, _ = allowedLog.w.Write(append(line, '\n'))
}

// allowedLog is the journal sink of allowAndLog: standard error in production; a test reads it back.
var allowedLog = struct {
	sync.Mutex
	w io.Writer
}{w: os.Stderr}
