//go:build laneboss_faults

package refusal

import (
	"os"
	"path/filepath"

	"laneboss.io/laneboss/internal/faults"
)

// The tagged mutant writes a harmless comment into the disposable policy file,
// so the real policy-byte hash check must fail. Release builds exclude this file.
func proposalPolicyFault(directory string) error {
	if faults.Get("refusal-writes-policy").Point == "" {
		return nil
	}
	f, err := os.OpenFile(filepath.Join(directory, "rules", "standing.md"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString("\n# Fault control: a proposal wrote policy bytes.\n")
	return err
}
