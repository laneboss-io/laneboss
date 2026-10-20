package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// The case supplies its real boot bundle. The production assembler executable
// supplies decoding, field-shape validation and assembly, including failures.
func TestDirtyBundle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "-I", "-B",
		filepath.Join("../../../e2e/v2/cases/dirty", "test_restore.py"), "--bundle")
	raw, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("dirty boot bundle failed: %v\n%s", err, raw)
	}
	var bundle map[string]json.RawMessage
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	base, err := json.Marshal(bundleInput(t))
	if err != nil {
		t.Fatal(err)
	}
	var input map[string]json.RawMessage
	if err := json.Unmarshal(base, &input); err != nil {
		t.Fatal(err)
	}
	for key, value := range bundle {
		input[key] = value
	}
	directory := t.TempDir()
	binary := filepath.Join(directory, "bundle-assemble")
	command = exec.CommandContext(ctx, "go", "build", "-o", binary, ".")
	if raw, err := command.CombinedOutput(); err != nil {
		t.Fatalf("real assembler build failed: %v\n%s", err, raw)
	}
	run := func(value map[string]json.RawMessage) ([]byte, []byte, error) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "input.json")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, binary, "--input", path)
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		err = command.Run()
		return stdout.Bytes(), stderr.Bytes(), err
	}
	stdout, stderr, err := run(input)
	if err != nil || len(stderr) != 0 {
		t.Fatalf("real dirty bundle refused: %v\n%s", err, stderr)
	}
	var assembled output
	if err := json.Unmarshal(stdout, &assembled); err != nil {
		t.Fatal(err)
	}
	var budget api.Budget
	if err := api.DecodeObject(bundle["budget"], &budget); err != nil {
		t.Fatal(err)
	}
	if assembled.Root.Budget != budget || budget.SpendMicros != 0 || budget.WallMS != 300000 || len(assembled.Lanes) != 2 {
		t.Fatal("assembler lost the zero-spend held fixture budget")
	}
	for _, lane := range assembled.Lanes {
		if lane.Budget != budget || lane.Task != assembled.Initial.Task {
			t.Fatal("assembled launch changed the case budget or task")
		}
	}
	profiles := false
	for _, document := range assembled.Documents {
		if document.Ref != assembled.Initial.Profiles {
			continue
		}
		profiles = true
		var grants api.RootGrantManifest
		if err := api.DecodeObject(document.Data, &grants); err != nil {
			t.Fatal(err)
		}
		if len(grants.Profiles) != 2 || len(grants.Resources) != 0 {
			t.Fatal("fixture budget requires an unexpected paid resource")
		}
		for _, profile := range grants.Profiles {
			if profile.Paid || profile.Provider != "serve-fixture" {
				t.Fatal("dirty case enrolled a paid model")
			}
		}
	}
	if !profiles {
		t.Fatal("assembler omitted the actual fixture profile manifest")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(bundle["budget"], &fields); err != nil {
		t.Fatal(err)
	}
	for _, field := range append(budgetKeys(fields), "extra") {
		changed := make(map[string]json.RawMessage, len(fields)+1)
		for key, value := range fields {
			changed[key] = value
		}
		reason := "missing"
		path := "$.budget." + field
		if field == "extra" {
			changed[field] = json.RawMessage("0")
			reason = "unknown"
			path = "$.budget.*"
		} else {
			delete(changed, field)
		}
		raw, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		input["budget"] = raw
		stdout, stderr, err := run(input)
		var exit *exec.ExitError
		var refusal api.Error
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || len(stdout) != 0 ||
			json.Unmarshal(stderr, &refusal) != nil || refusal.Code != api.CodeInvalid ||
			!strings.Contains(refusal.Message, "field="+path+";") ||
			!strings.Contains(refusal.Message, "reason="+reason) {
			t.Fatalf("real assembler missed %s %s: %v\n%s", reason, field, err, stderr)
		}
		t.Log("RED " + field + ": " + refusal.Message)
	}
	t.Log("GREEN actual dirty boot bundle: zero-spend budget reaches root and both launches")
}

func budgetKeys(fields map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
