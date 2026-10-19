//go:build linux

package main

import "runtime"

// The helper dispatches on the main goroutine. Reserve the process leader so
// a namespace worker cannot run there and leave a parked leader in a sandbox.
func init() {
	runtime.LockOSThread()
}
