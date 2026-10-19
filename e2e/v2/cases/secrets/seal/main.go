// secret-seal is a disposable-box input producer, never an installed RPC.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets"
)

type input struct {
	Config   string        `json:"config"`
	Name     string        `json:"name"`
	Version  string        `json:"version"`
	Key      api.SecretKey `json:"key"`
	Material string        `json:"material"`
}

func privateRead(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("private absolute input required")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, errors.New("ordinary private input required")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() > limit {
		return nil, errors.New("private bounded input required")
	}
	identity, ok := before.Sys().(*syscall.Stat_t)
	if !ok || identity.Uid != uint32(os.Geteuid()) || identity.Nlink != 1 {
		return nil, errors.New("private input owner or links differ")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("private input cannot open")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("private input changed")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) != before.Size() || len(data) == 0 {
		return nil, errors.New("private input size differs")
	}
	return data, nil
}

func produce(path string) (api.SecretStageRequest, error) {
	var result api.SecretStageRequest
	raw, err := privateRead(path, 16384)
	if err != nil {
		return result, err
	}
	var request input
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		return result, errors.New("invalid seal input")
	}
	material, err := privateRead(request.Material, 65520)
	if err != nil {
		return result, err
	}
	defer clear(material)
	return secrets.SealStage(request.Config, request.Key, request.Name, request.Version,
		api.SecretMaterial{Bytes: material})
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "secret-seal: private input file required")
		os.Exit(2)
	}
	result, err := produce(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "secret-seal: input or encryption refused")
		os.Exit(1)
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		os.Exit(1)
	}
}
