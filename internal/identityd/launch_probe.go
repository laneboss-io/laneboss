//go:build laneboss_faults

package identityd

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
)

// LaunchProbe exercises the real launch handoff. File names are fixture stdio,
// never identity inputs. The test keeps this caller alive while inspecting the
// root's ancestry, so a missing detach cannot be hidden by the probe's exit.
func LaunchProbe(stdin io.Reader, stdout, stderr io.Writer) int {
	reader := bufio.NewReaderSize(stdin, MaxRequestBytes+1)
	line, err := reader.ReadSlice('\n')
	var input struct {
		Spec   LaunchSpec `json:"spec"`
		Input  string     `json:"input"`
		Output string     `json:"output"`
		Error  string     `json:"error"`
	}
	if err != nil || len(line) > MaxRequestBytes || json.Unmarshal(line, &input) != nil {
		return 2
	}
	in, err := os.Open(input.Input)
	if err != nil {
		return 2
	}
	defer in.Close()
	out, err := os.OpenFile(input.Output, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return 2
	}
	defer out.Close()
	errout, err := os.OpenFile(input.Error, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return 2
	}
	defer errout.Close()
	ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer cancel()
	result, err := Launch(ctx, input.Spec, LaunchIO{in, out, errout})
	if err != nil {
		return launchFailure(err, stderr)
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		return 2
	}
	var release [1]byte
	if _, err := io.ReadFull(reader, release[:]); err != nil || release[0] != 'q' {
		return 2
	}
	return 0
}
