package main

import (
	"bytes"
	"os"
	"strconv"
	"testing"
)

func TestWritesWorktree(t *testing.T) {
	data := []byte(strconv.Itoa(os.Getpid()))
	if err := os.WriteFile("ordinary-proof", data, 0600); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile("ordinary-proof")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, actual) {
		t.Fatal("worktree write did not retain the actual process id")
	}
}
