package admin

// FixedBootstrapEntry is an internal descriptor-only entry, not an RPC or
// administrator authority. The sealed payload still selects every operation.
const FixedBootstrapEntry = "--fixed-bootstrap"

const bootstrapUnknownExit = 99

var bootstrapStageCodes = map[string]int{
	"prompt.reference":       139,
	"prompt.seals":           140,
	"prompt.read":            141,
	"prompt.measure":         142,
	"prompt.digest":          143,
	"descriptors.inventory":  144,
	"descriptors.missing":    145,
	"descriptors.socket":     146,
	"descriptors.seals":      147,
	"descriptors.projection": 148,
	"descriptors.retain":     149,
	"exec_proof.create":      150,
	"exec_proof.transfer":    151,
	"limit.nofile_read":      152,
	"limit.nofile_set":       153,
	"limit.nofile_readback":  154,
	"entry.route":            80, "entry.arguments": 81, "entry.config": 82,
	"entry.context": 83, "input.decode": 84, "entry.route_close": 85,
	"unclassified": bootstrapUnknownExit,
	"input.seals":  100, "input.read": 101, "identity": 102, "groups": 103,
	"control.peer": 104, "release.pipe": 105, "capabilities.read": 106,
	"capabilities.retained": 107, "capabilities.absent": 108,
	"input.executable": 109, "input.argument": 110, "cwd": 111,
	"readiness.write": 112, "dumpable": 113, "no_new_privileges": 114,
	"limit.cpu": 115, "limit.core": 116, "landlock.abi": 117,
	"landlock.create": 118, "landlock.path": 119, "landlock.open": 120,
	"landlock.type": 121, "landlock.rule": 122, "landlock.restrict": 123,
	"seccomp.architecture": 124, "seccomp.install": 125,
	"descriptors.cloexec": 136, "release.token": 137, "release.eof": 138,
	"readiness.close": 129, "vendor.exec": 130, "capture.input": 131,
	"capture.pipe": 132, "capture.file": 133, "capture.cloexec": 134,
	"capture.readiness": 135,
}

func bootstrapExitStage(code int) string {
	// The external bwrap setup precedes our Go entry. Its own fatal setup
	// errors use 1; Go runtime/package initialization failures normally use 2.
	if code == 1 {
		return "bwrap_setup"
	}
	if code == 2 {
		return "go_runtime_or_init"
	}
	if code == 126 || code == 127 {
		return "loader_or_exec"
	}
	for reason, candidate := range bootstrapStageCodes {
		if code == candidate {
			return reason
		}
	}
	return "other"
}
