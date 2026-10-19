package eventstore

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"laneboss.io/laneboss/internal/contextio"
)

// ReadOutputTail opens only the launcher's fixed output.log below a recorded
// lane. It pins the state root, rejects links and devices, and creates no files.
func ReadOutputTail(c *Configuration, lane string, count int) ([]string, bool, error) {
	return ReadOutputTailContext(context.Background(), c, lane, count)
}

func ReadOutputTailContext(ctx context.Context, c *Configuration, lane string, count int) ([]string, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if !laneGrammar.MatchString(lane) || count < 1 || count > 2000 {
		return nil, false, Refuse("invalid log selection")
	}
	d, err := c.OpenDirectory(false)
	if err != nil || d == nil {
		return nil, false, err
	}
	defer d.Close()
	marker, err := d.Marker()
	if err != nil || object(marker["store"]) == nil {
		return nil, false, Integrity("the log directory has no recorded store owner")
	}
	path := filepath.Join("lanes", lane, "output.log")
	if _, err = checkedBelow(d.Path, path); os.IsNotExist(err) {
		return []string{}, false, nil
	} else if err != nil {
		return nil, false, err
	}
	root, err := os.OpenRoot(d.Path)
	if err != nil {
		return nil, false, err
	}
	defer root.Close()
	identity, err := root.Stat(".")
	if err != nil || !os.SameFile(identity, d.identity) {
		return nil, false, Integrity("the log state directory changed")
	}
	file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, false, Integrity("the recorded output log is not a regular file")
	}
	// Bound I/O even when a recorded log is very large. A partial first line is
	// dropped; an oversized complete vendor event is withheld by the parser.
	start := max(int64(0), info.Size()-16*1024*1024)
	data, err := io.ReadAll(&contextio.Reader{Context: ctx, Source: io.NewSectionReader(file, start, info.Size()-start)})
	if err != nil {
		return nil, false, err
	}
	if start > 0 {
		at := bytes.IndexByte(data, '\n')
		if at < 0 {
			return []string{""}, true, nil
		}
		data = data[at+1:]
	}
	data = bytes.TrimSuffix(data, []byte{'\n'})
	lines := bytes.Split(data, []byte{'\n'})
	if len(data) == 0 {
		return []string{}, true, nil
	}
	if len(lines) > count {
		lines = lines[len(lines)-count:]
	}
	result := make([]string, len(lines))
	for i, line := range lines {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		result[i] = string(line)
	}
	return result, true, nil
}
