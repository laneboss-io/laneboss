// Package v2 provides the frozen compatibility matrix, 0.5.0 rollback boundary
// validators, and historical adversarial fixture inventory for lb-v2-migration.
package v2

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

//go:embed compatibility.json
var matrixBytes []byte

type RollbackBoundary struct {
	Version                      string              `json:"version"`
	Protocol                     string              `json:"protocol"`
	Commit                       string              `json:"commit,omitempty"`
	RequiresFrozenBackup         bool                `json:"requires_frozen_backup,omitempty"`
	ForbidsV2StoreRelink         bool                `json:"forbids_v2_store_relink,omitempty"`
	IncompatibleConfigKeys       []string            `json:"incompatible_config_keys,omitempty"`
	IncompatibleRunnerKeys       []string            `json:"incompatible_runner_keys,omitempty"`
	IncompatibleLaneKeys         []string            `json:"incompatible_lane_keys,omitempty"`
	IncompatibleEventKinds       []string            `json:"incompatible_event_kinds,omitempty"`
	IncompatibleEventFields      map[string][]string `json:"incompatible_event_fields,omitempty"`
	IncompatibleStates           []string            `json:"incompatible_states,omitempty"`
	IncompatibleProjectionFields []string            `json:"incompatible_projection_fields,omitempty"`
}

type CompatibilityMatrix struct {
	Schema                   string                      `json:"schema"`
	TargetSchema             uint32                      `json:"target_schema"`
	TargetProtocol           string                      `json:"target_protocol"`
	SupportedSourceVersions  []string                    `json:"supported_source_versions"`
	SupportedSourceProtocols []string                    `json:"supported_source_protocols"`
	SupportedDecisionSchemas []int                       `json:"supported_decision_schemas"`
	RollbackBoundaries       map[string]RollbackBoundary `json:"rollback_boundaries"`
	AdversarialAdditionsIDs  []string                    `json:"adversarial_additions_ids"`
}

type AdversarialCase struct {
	ID      string `json:"id"`
	Class   string `json:"class"`
	Kind    string `json:"kind"`
	Family  string `json:"family,omitempty"`
	Fixture string `json:"fixture"`
	CWD     string `json:"cwd"`
	Command string `json:"command"`
}

type AdversarialFile struct {
	SchemaVersion int               `json:"schema_version"`
	Scope         string            `json:"scope"`
	Cases         []AdversarialCase `json:"cases"`
}

type AdversarialInventory struct {
	SHA256 string            `json:"sha256"`
	Bytes  int64             `json:"bytes"`
	IDs    []string          `json:"ids"`
	Cases  []AdversarialCase `json:"cases"`
}

func Matrix() (CompatibilityMatrix, error) {
	var m CompatibilityMatrix
	dec := json.NewDecoder(bytes.NewReader(matrixBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return CompatibilityMatrix{}, err
	}
	return m, nil
}

func MatrixSHA256() string {
	sum := sha256.Sum256(matrixBytes)
	return hex.EncodeToString(sum[:])
}

func SupportedSourceVersion(v string) bool {
	m, err := Matrix()
	if err != nil {
		return false
	}
	for _, s := range m.SupportedSourceVersions {
		if s == v {
			return true
		}
	}
	return false
}

func SupportedSourceProtocol(p string) bool {
	m, err := Matrix()
	if err != nil {
		return false
	}
	for _, s := range m.SupportedSourceProtocols {
		if s == p {
			return true
		}
	}
	return false
}

// VerifyAdversarialAdditions validates the exact bytes and case IDs of
// e2e-rows/adversarial-additions.json for preservation in migration manifests.
func VerifyAdversarialAdditions(raw []byte) (AdversarialInventory, error) {
	m, err := Matrix()
	if err != nil {
		return AdversarialInventory{}, err
	}
	var parsed AdversarialFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&parsed); err != nil {
		return AdversarialInventory{}, fmt.Errorf("invalid adversarial-additions JSON: %w", err)
	}
	if parsed.SchemaVersion != 1 {
		return AdversarialInventory{}, fmt.Errorf("unsupported adversarial-additions schema_version %d", parsed.SchemaVersion)
	}
	if len(parsed.Cases) != len(m.AdversarialAdditionsIDs) {
		return AdversarialInventory{}, fmt.Errorf("adversarial-additions count = %d, want %d", len(parsed.Cases), len(m.AdversarialAdditionsIDs))
	}
	ids := make([]string, 0, len(parsed.Cases))
	for i, c := range parsed.Cases {
		if c.ID != m.AdversarialAdditionsIDs[i] {
			return AdversarialInventory{}, fmt.Errorf("adversarial case[%d] id = %q, want %q", i, c.ID, m.AdversarialAdditionsIDs[i])
		}
		if c.Command == "" || c.CWD == "" || c.Fixture == "" {
			return AdversarialInventory{}, fmt.Errorf("adversarial case %q has empty required fields", c.ID)
		}
		ids = append(ids, c.ID)
	}
	sum := sha256.Sum256(raw)
	return AdversarialInventory{
		SHA256: hex.EncodeToString(sum[:]),
		Bytes:  int64(len(raw)),
		IDs:    ids,
		Cases:  parsed.Cases,
	}, nil
}

func LoadAdversarialAdditions(path string) (AdversarialInventory, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return AdversarialInventory{}, nil, err
	}
	inv, err := VerifyAdversarialAdditions(raw)
	if err != nil {
		return AdversarialInventory{}, nil, err
	}
	return inv, raw, nil
}

// Check050Compatibility returns the deterministic list of incompatibilities that
// prevent 0.5.0 from reading or running against the given config TOML, events, and projections.
func Check050Compatibility(configTOML []byte, events []map[string]any, projections []map[string]any) ([]string, error) {
	m, err := Matrix()
	if err != nil {
		return nil, err
	}
	b := m.RollbackBoundaries["0.5.0"]
	var reasons []string

	if len(configTOML) > 0 {
		var cfg map[string]any
		if _, err := toml.Decode(string(configTOML), &cfg); err != nil {
			return nil, fmt.Errorf("invalid config.toml: %w", err)
		}
		for _, k := range b.IncompatibleConfigKeys {
			if _, ok := cfg[k]; ok {
				reasons = append(reasons, "config.toml:"+k)
			}
		}
		if lanesTbl, ok := cfg["lanes"].(map[string]any); ok {
			for _, k := range b.IncompatibleLaneKeys {
				if _, exists := lanesTbl[k]; exists {
					reasons = append(reasons, "config.toml:lanes."+k)
				}
			}
		}
		if runnersTbl, ok := cfg["runners"].(map[string]any); ok {
			runnerNames := make([]string, 0, len(runnersTbl))
			for name := range runnersTbl {
				runnerNames = append(runnerNames, name)
			}
			sort.Strings(runnerNames)
			for _, name := range runnerNames {
				r, ok := runnersTbl[name].(map[string]any)
				if !ok {
					continue
				}
				for _, k := range b.IncompatibleRunnerKeys {
					if _, exists := r[k]; exists {
						reasons = append(reasons, fmt.Sprintf("config.toml:runners.%s.%s", name, k))
					}
				}
				for _, cmdField := range []string{"command", "resume"} {
					if arr, ok := r[cmdField].([]any); ok {
						for _, arg := range arr {
							if s, ok := arg.(string); ok && strings.Contains(s, "{session}") {
								reasons = append(reasons, fmt.Sprintf("config.toml:runners.%s.%s:{session}", name, cmdField))
								break
							}
						}
					}
				}
			}
		}
	}

	incompatKinds := make(map[string]bool, len(b.IncompatibleEventKinds))
	for _, k := range b.IncompatibleEventKinds {
		incompatKinds[k] = true
	}
	incompatStates := make(map[string]bool, len(b.IncompatibleStates))
	for _, s := range b.IncompatibleStates {
		incompatStates[s] = true
	}

	for _, ev := range events {
		kind, _ := ev["kind"].(string)
		seq := ev["seq"]
		if incompatKinds[kind] {
			reasons = append(reasons, fmt.Sprintf("event:%v:kind:%s", seq, kind))
		}
		payload, _ := ev["payload"].(map[string]any)
		if payload != nil {
			for _, field := range b.IncompatibleEventFields[kind] {
				if _, ok := payload[field]; ok {
					reasons = append(reasons, fmt.Sprintf("event:%v:%s.%s", seq, kind, field))
				}
			}
			if kind == "lane.state" {
				if st, _ := payload["state"].(string); incompatStates[st] {
					reasons = append(reasons, fmt.Sprintf("event:%v:lane.state:%s", seq, st))
				}
			}
		}
	}

	for _, proj := range projections {
		laneName, _ := proj["lane"].(string)
		for _, field := range b.IncompatibleProjectionFields {
			if _, ok := proj[field]; ok {
				reasons = append(reasons, fmt.Sprintf("projection:%s:%s", laneName, field))
			}
		}
		if st, _ := proj["state"].(string); incompatStates[st] {
			reasons = append(reasons, fmt.Sprintf("projection:%s:state:%s", laneName, st))
		}
	}

	return reasons, nil
}
