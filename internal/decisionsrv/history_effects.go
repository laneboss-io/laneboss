package decisionsrv

import "path/filepath"

// HistoryFileEffects resolves the same configured paths used by captureDecision
// and injectHistory. It observes configuration only and starts no worker or judge.
// SQLite opens may recover journals even for history retrieval.
func HistoryFileEffects(directory, operation, configuration string) (reads, writes []string, stateRoot string, err error) {
	o, err := openOrg(directory)
	if err != nil {
		return nil, nil, "", err
	}
	reads = []string{filepath.Join(o.home, "org.toml"), filepath.Join(o.home, "shared/services/history.toml"), o.db}
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		writes = append(writes, o.db+suffix)
	}
	switch operation {
	case "capture":
		if configuration == "" {
			configuration = str(o.history["configuration"])
		}
		c, err := loadConfiguration(configuration, true)
		if err != nil {
			return nil, nil, "", err
		}
		// askChoice writes ownership and judge egress state through the same
		// checked configuration root as the other CLI state operations.
		stateRoot = c.state
		reads = append(reads, filepath.Join(c.directory, "config.toml"))
		writes = append(writes, o.captureLog, o.review)
	case "inject":
		guard, err := o.path("shared/state/history/resident-start.json")
		if err != nil {
			return nil, nil, "", err
		}
		writes = append(writes, o.log, guard, o.socket)
	default:
		return nil, nil, "", invalid("unknown history file-effects operation")
	}
	return reads, writes, stateRoot, nil
}
