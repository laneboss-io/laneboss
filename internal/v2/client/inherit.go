package client

import (
	"errors"
	"io"
	"os"
	"os/exec"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// InheritLaneCommand explicitly preserves the two fixed lane projections when
// a Go runner invokes a child CLI. It never forwards the runner's other FDs.
// The caller must close the returned duplicates after Start (also on failure).
// All subsequent authority still comes from the child's native service peer.
func InheritLaneCommand(command *exec.Cmd, config string) (io.Closer, error) {
	if command == nil || command.Process != nil || len(command.ExtraFiles) != 0 {
		return nil, wire.Invalid("lane descriptor handoff requires an unstarted command without extra capabilities")
	}
	if bound := os.Getenv("LANEBOSS_CONFIG"); bound != "" && bound != config {
		return nil, &api.Error{Code: api.CodeConflict, Message: "child descriptor handoff conflicts with active configuration", Instead: "Keep this process bound and use a separately bound process."}
	}
	files, err := wire.RetainLaneDescriptors(config, release.Version)
	if err != nil {
		return nil, err
	}
	return attachLaneDescriptors(command, files)
}

type laneFiles []wire.InheritedFile

func (files laneFiles) Close() error {
	var result error
	for _, item := range files {
		result = errors.Join(result, item.File.Close())
	}
	return result
}

func attachLaneDescriptors(command *exec.Cmd, files []wire.InheritedFile) (io.Closer, error) {
	owned := laneFiles(files)
	maximum := 0
	seen := make(map[int]bool)
	for _, item := range files {
		// The installed runtime has at most 128 objects. Bound even a damaged
		// projection number before allocating a sparse os/exec descriptor table.
		if item.FD < 6 || item.FD > 4096 || item.File == nil || seen[item.FD] {
			return nil, errors.Join(wire.Invalid("invalid fixed child descriptor inventory"), owned.Close())
		}
		seen[item.FD] = true
		maximum = max(maximum, item.FD)
	}
	if len(files) != 2 {
		return nil, errors.Join(wire.Invalid("child lane handoff requires exactly its binding and socket"), owned.Close())
	}
	if err := inheritedCloseOnExec(); err != nil {
		return nil, errors.Join(err, owned.Close())
	}
	extra := make([]*os.File, maximum-2)
	for _, item := range files {
		extra[item.FD-3] = item.File
	}
	command.ExtraFiles = extra
	return owned, nil
}
