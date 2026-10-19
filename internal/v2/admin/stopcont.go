package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
)

// The durable local fence is already saved. This value-free notice does not
// grant live containment authentication to the ended process.
func journalStopExit(ctx context.Context, record leaseRecord) error {
	if !releaseStop(record) {
		return nil
	}
	var writer io.Writer = os.Stderr
	if trace, _ := ctx.Value(helperTimingKey{}).(*helperRequestTrace); trace != nil && trace.timing != nil {
		writer = trace.timing
	}
	raw, err := json.Marshal(struct {
		Event string `json:"event"`
		Note  string `json:"note"`
	}{"credential_stop", record.Credentials.Stop.Note})
	if err != nil {
		return errors.Join(errHelperJournal, err)
	}
	raw = append(raw, '\n')
	n, err := writer.Write(raw)
	if err != nil || n != len(raw) {
		return errors.Join(errHelperJournal, io.ErrShortWrite, err)
	}
	return nil
}
