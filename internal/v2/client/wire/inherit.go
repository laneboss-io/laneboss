package wire

import "os"

// InheritedFile is a duplicate of one fixed lane projection. FD is its required
// number in the child: the immutable projection link still names that number.
type InheritedFile struct {
	FD   int
	File *os.File
}
