//go:build !laneboss_faults

package faults

import (
	"os"
	"syscall"
)

func Get(string) Options                             { return Options{} }
func Reach(string) error                             { return nil }
func SQL(string) error                               { return nil }
func DirectoryFlock(f *os.File, operation int) error { return syscall.Flock(int(f.Fd()), operation) }
func Sync(f *os.File) error                          { return f.Sync() }
func BeforeJudgeStart()                              {}

func ProcStat(path string) ([]byte, error) { return os.ReadFile(path) }
