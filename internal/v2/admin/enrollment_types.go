package admin

import "os"

// An opened administrator root, never an API path or a pre-resolved source.
// Production opens the fixed release root with owner zero. Component callers
// inside this package may supply their own real filesystem root and owner.
type enrollmentFiles struct {
	root  *os.Root
	base  string
	owner uint32
}
