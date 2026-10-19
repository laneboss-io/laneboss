package orghook

import (
	"path/filepath"
	"sort"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/decisionsrv"
	"laneboss.io/laneboss/internal/faults"
)

func appendLanebossWrite(targets *[]string, value string) {
	if value == "" || value == "-" {
		return
	}
	for _, existing := range *targets {
		if existing == value {
			return
		}
	}
	*targets = append(*targets, value)
}

func lanebossDeclaredWrites(call cliCall) []string {
	targets := append([]string{}, call.writes...)
	for _, database := range call.databases {
		appendLanebossWrite(&targets, database)
		appendLanebossWrite(&targets, database+"-journal")
		appendLanebossWrite(&targets, database+"-wal")
		appendLanebossWrite(&targets, database+"-shm")
	}
	return targets
}

func lanebossCommand(argv []string, directory string) (command, error) {
	result := command{argv: argv, directory: directory, opaque: true}
	call, supported := inspectCLI(argv[1:])
	if !supported {
		return result, invalid("the tool or command has no file-effects adapter")
	}
	// This restores the actual missing-adapter behavior. Release builds have
	// inert fault accessors and cannot select this branch.
	if faults.Get("orghook-cli-drop").Point != "" {
		if err := faults.Reach("orghook-cli-drop"); err != nil {
			return result, err
		}
		return result, nil
	}
	if call.help || call.version {
		result.opaque = false
		return result, nil
	}
	historyComplete := len(call.history) > 0
	historyConfig := ""
	if values := call.values["--config"]; len(values) > 0 {
		historyConfig = values[len(values)-1]
	}
	for org, operation := range call.history {
		path, err := pathAt(org, directory)
		if err != nil {
			return result, err
		}
		reads, writes, state, err := decisionsrv.HistoryFileEffects(path, operation, historyConfig)
		if err != nil {
			// An unreadable org cannot execute these effects. Keep the known
			// selector read and an incomplete receipt; the CLI reports why.
			call.partial = true
			historyComplete = false
			continue
		}
		result.reads = append(result.reads, reads...)
		result.managedWrites = append(result.managedWrites, writes...)
		if state != "" {
			result.stateRoot = state
			result.stateWrites = []string{state}
		}
	}
	// Parsing grants no command authority. Unannotated calls keep their known
	// effects and an incomplete receipt; the CLI checks authority when run.
	for _, path := range call.reads {
		if path != "-" {
			result.reads = append(result.reads, path)
		}
	}
	result.metadata = append(result.metadata, call.metadata...)
	if call.effects == nil {
		result.writes = lanebossDeclaredWrites(call)
		result.opaque = !historyComplete
		return result, nil
	}
	result.writes = append(result.writes, call.writes...)
	name := ""
	if call.effects.Config != "" {
		values := call.values[call.effects.Config]
		if len(values) > 0 {
			name = values[len(values)-1]
		}
	}
	configuration, err := config.Load(name)
	if err != nil {
		return result, invalid(configInvalid(err))
	}
	state, err := pathAt(configuration.StateDir, directory)
	if err != nil {
		return result, err
	}
	result.reads = append(result.reads, configuration.ConfigFile)
	for path := range configuration.RuleBytes {
		result.reads = append(result.reads, filepath.Join(configuration.ConfigDir, path))
	}
	// The named state root is kept separate from shell redirects. Only this
	// adapter's declared effects receive the checked CLI state-write scope.
	result.stateRoot = state
	// Read-only views also open SQLite mode=rw and can recover its journal.
	// Report's file owner channels resolve under StateDir and are delivered only
	// to the human. They are covered by this checked state scope, with no ordinary
	// declared write for either a supervisor-addressed or human-addressed report.
	result.stateWrites = []string{state}
	result.metadata = append(result.metadata, state)
	for _, option := range call.effects.Reads {
		for _, path := range call.values[option] {
			if path != "-" {
				result.reads = append(result.reads, path)
			}
		}
	}
	// Decision reads use SQLite mode=rw and may recover a hot journal. Declare
	// that effect and require the DB and its sidecars to stay in this state root.
	for _, database := range call.databases {
		path, err := pathAt(database, directory)
		if err != nil {
			return result, err
		}
		if !inside(path, state) {
			for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
				appendLanebossWrite(&result.writes, database+suffix)
			}
		}
		result.stateWrites = []string{state}
	}
	sort.Strings(result.reads)
	result.opaque = call.partial
	return result, nil
}
