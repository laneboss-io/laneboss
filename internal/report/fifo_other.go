//go:build !linux

package report

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

func createFIFO(root *os.Root, directory *os.File, name string) error {
	pinned, err := directory.Stat()
	if err != nil {
		return err
	}
	current, err := os.Stat(root.Name())
	if err != nil || !os.SameFile(pinned, current) {
		return fmt.Errorf("terminal directory was replaced")
	}
	if err = unix.Mkfifo(filepath.Join(root.Name(), name), 0600); err != nil {
		return err
	}
	current, err = os.Stat(root.Name())
	if err != nil || !os.SameFile(pinned, current) {
		return fmt.Errorf("terminal directory was replaced")
	}
	return nil
}
