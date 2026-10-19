// Command grants_seal creates a disposable random task-secret canary and seals
// it with the operator's existing client primitive. Plaintext never leaves
// this process; this executable enrolls nothing and contacts no service.
package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets"
)

func run() error {
	path := flag.String("input", "", "retained public key and canary metadata")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		return fmt.Errorf("one public sealing input file is required")
	}
	raw, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	var input struct {
		Config  string        `json:"config"`
		Key     api.SecretKey `json:"key"`
		Name    string        `json:"name"`
		Version string        `json:"version"`
	}
	if err := api.DecodeObject(raw, &input); err != nil {
		return err
	}
	material := make([]byte, 32)
	defer clear(material)
	if _, err := rand.Read(material); err != nil {
		return err
	}
	sealed, err := secrets.SealStage(input.Config, input.Key, input.Name, input.Version, api.SecretMaterial{Bytes: material})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(sealed)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "task canary sealing failed:", err)
		os.Exit(1)
	}
}
