package box

import (
	"fmt"
	"io"
	"os/exec"

	"laneboss.io/laneboss/internal/boxcore"
)

func check(cfg *boxcore.Config, provider string, stdout, stderr io.Writer, env environment) int {
	code := boxcore.ExitOK
	var writeErr error
	row := func(what string, ok bool) {
		prefix := "ok"
		if !ok {
			prefix = "FAIL"
			code = boxcore.ExitUsage
		}
		if _, err := fmt.Fprintf(stdout, "%s: %s\n", prefix, what); err != nil {
			writeErr = err
		}
	}
	row("config", true)
	programs := []string{"git"}
	if cfg.AWS != nil && (provider == "" || provider == "aws") {
		row("aws provider", true)
		programs = append(programs, "aws", "ssh", "curl")
	}
	if cfg.GCP != nil && (provider == "" || provider == "gcp") {
		row("gcp provider", true)
		programs = append(programs, "gcloud")
	}
	l, err := env.openLedger(cfg, stderr)
	if err == nil {
		err = l.Writable()
	}
	row("ledger writable", err == nil)
	for _, program := range programs {
		_, err := exec.LookPath(program)
		row(program, err == nil)
	}
	return finish(code, nil, writeErr, stderr)
}
