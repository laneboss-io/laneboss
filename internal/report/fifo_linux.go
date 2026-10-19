package report

import (
	"golang.org/x/sys/unix"
	"os"
)

func createFIFO(root *os.Root, directory *os.File, name string) error {
	return unix.Mkfifoat(int(directory.Fd()), name, 0600)
}
