package codex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

func id(value api.ID) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func digest(value api.Digest) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func label(value string) bool {
	return len(value) > 0 && len(value) <= 256 && utf8.ValidString(value) && !strings.HasPrefix(value, "-") &&
		strings.IndexFunc(value, func(c rune) bool { return c <= 32 || c == 127 }) < 0
}

func absolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator) &&
		utf8.ValidString(path) && strings.IndexFunc(path, func(c rune) bool { return c < 32 || c == 127 }) < 0
}

func uuid(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func executable(value api.Executable) bool {
	return id(value.ID) && digest(value.SHA256) && label(value.Version)
}

func blob(value api.BlobRef) bool {
	return id(value.ID) && digest(value.SHA256) && value.Bytes >= 0 && value.Bytes <= api.MaxObjectBytes && label(value.Class)
}

func privateHome(home api.PrivateHome) bool {
	return id(home.ID) && id(home.WorkspaceID) && id(home.HistoryID) &&
		(home.VendorDirectory == ".codex" || absolute(home.VendorDirectory) && filepath.Base(home.VendorDirectory) == ".codex" &&
			absolute(filepath.Dir(home.VendorDirectory)))
}

func validateRequest(request api.RunnerRequest) error {
	if !id(request.Target.LifeID) || request.Target.Run < 1 || request.Target.Run > 1<<53-1 || !id(request.LogicalTurnID) ||
		!id(request.Session.ID) || !id(request.Session.HistoryID) || request.Session.Driver != api.DriverCodex || !privateHome(request.Home) ||
		request.Session.HomeID != request.Home.ID || !absolute(request.Session.LogicalCWD) ||
		!executable(request.Executable) || !blob(request.Prompt) || request.Prompt.Bytes == 0 ||
		!id(request.Slot.ID) || !id(request.Slot.ProfileID) || !id(request.Slot.ProfileGrantID) || !id(request.Slot.LeaseID) ||
		!label(request.Model) || !label(request.Effort) {
		return problem(api.CodeInvalid, "Codex request has an invalid identity, path or input reference")
	}
	if request.Session.HistoryID != request.Home.HistoryID {
		return problem(api.CodeIntegrity, "Codex session history differs from its private home")
	}
	budget := request.Budget
	if budget.WallMS <= 0 || budget.WallMS > 1<<53-1 || budget.CPUSeconds > 1<<53-1 ||
		budget.MemoryBytes == 0 || budget.MemoryBytes > 1<<53-1 || budget.Processes == 0 ||
		budget.DiskBytes == 0 || budget.DiskBytes > 1<<53-1 || budget.SpendMicros < 0 ||
		budget.SpendMicros > 1<<53-1 || !label(budget.Currency) {
		return problem(api.CodeBudget, "Codex needs a finite valid launch budget")
	}
	return nil
}

func timestamp(value api.Timestamp) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, string(value))
	if err != nil || !strings.HasSuffix(string(value), "Z") {
		return time.Time{}, problem(api.CodeInvalid, "Codex observation time is invalid")
	}
	return parsed, nil
}

func quiescent(value api.ProcessObservation, target api.LifeRef) bool {
	if _, err := timestamp(value.ObservedAt); err != nil {
		return false
	}
	if (value.ExitCode == nil) == (value.Signal == nil) {
		return false
	}
	if value.ExitCode != nil && (*value.ExitCode < -1<<31 || *value.ExitCode > 1<<31-1) {
		return false
	}
	if value.Signal != nil && (*value.Signal <= 0 || *value.Signal > 1<<31-1) {
		return false
	}
	return value.Handle.Target == target && id(value.Handle.ID) && id(value.Handle.ContainmentID) &&
		label(value.Handle.Generation) && value.State == "exited" && value.Survivors != nil && *value.Survivors == 0 &&
		(value.ExitCode != nil || value.Signal != nil)
}

// Check file identity before/after opening and hashing. The namespace helper
// must recheck these pins at release; this preflight cannot close a later race.
func verifyArtifact(path string, pin api.Executable) error {
	before, err := os.Lstat(path)
	if err != nil {
		return problem(api.CodePrerequisite, "Codex vendor or self-helper path is absent")
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 || before.Mode().Perm()&0111 == 0 || linked(before) {
		return problem(api.CodeIntegrity, "Codex artifact is linked, writable or not executable")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return problem(api.CodePrerequisite, "Codex artifact cannot be opened")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || linked(after) {
		return problem(api.CodeIntegrity, "Codex artifact changed while opening")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return problem(api.CodeIntegrity, "Codex artifact cannot be hashed completely")
	}
	final, err := f.Stat()
	if err != nil || final.Size() != after.Size() || final.ModTime() != after.ModTime() ||
		api.Digest(hex.EncodeToString(hash.Sum(nil))) != pin.SHA256 {
		return problem(api.CodeIntegrity, "Codex artifact differs from its pinned bytes")
	}
	return nil
}

func linked(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return !ok || stat.Nlink != 1
}

// decode rejects duplicate keys at every depth, invalid UTF-8, unknown fields,
// nonobjects, trailing values and oversized records. It does not print input.
func decode(data []byte, destination any) error {
	if err := api.DecodeObject(data, destination); err != nil {
		return problem(api.CodeIntegrity, "Codex JSON record does not match its exact required schema")
	}
	return nil
}

func decodeJSON(data []byte, destination any, strict bool) error {
	if len(data) == 0 || len(data) > api.MaxObjectBytes || !utf8.Valid(data) || !validSurrogates(data) {
		return problem(api.CodeIntegrity, "Codex JSON record has invalid bytes or size")
	}
	check := json.NewDecoder(bytes.NewReader(data))
	check.UseNumber()
	if err := objectTokens(check, strict); err != nil {
		return err
	}
	if _, err := check.Token(); err != io.EOF {
		return problem(api.CodeIntegrity, "Codex JSON record has trailing data")
	}
	reader := json.NewDecoder(bytes.NewReader(data))
	if strict {
		reader.DisallowUnknownFields()
	}
	if err := reader.Decode(destination); err != nil {
		return problem(api.CodeIntegrity, "Codex JSON record does not match its schema")
	}
	return nil
}

func objectTokens(reader *json.Decoder, strict bool) error {
	first, err := reader.Token()
	if err != nil || first != json.Delim('{') {
		return problem(api.CodeIntegrity, "Codex JSON record must be one object")
	}
	return compositeTokens(reader, json.Delim('{'), 0, strict)
}

func compositeTokens(reader *json.Decoder, opening json.Delim, depth int, strict bool) error {
	if depth > 64 {
		return problem(api.CodeIntegrity, "Codex JSON nesting exceeds the parser bound")
	}
	seen := map[string]bool{}
	for reader.More() {
		if opening == '{' {
			key, err := reader.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return problem(api.CodeIntegrity, "Codex JSON has an invalid or duplicate key")
			}
			seen[name] = true
		}
		value, err := reader.Token()
		if err != nil || (strict && value == nil) {
			return problem(api.CodeIntegrity, "Codex JSON has an invalid or null value")
		}
		if number, ok := value.(json.Number); ok {
			f, err := strconv.ParseFloat(string(number), 64)
			if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
				return problem(api.CodeIntegrity, "Codex JSON number is not finite")
			}
			if !strings.ContainsAny(string(number), ".eE") {
				integer, err := strconv.ParseInt(string(number), 10, 64)
				if err != nil || integer > 1<<53-1 || integer < -(1<<53-1) {
					return problem(api.CodeIntegrity, "Codex JSON integer exceeds the exact range")
				}
			}
		}
		if delimiter, ok := value.(json.Delim); ok {
			if delimiter != '{' && delimiter != '[' {
				return problem(api.CodeIntegrity, "Codex JSON has an unexpected delimiter")
			}
			if err := compositeTokens(reader, delimiter, depth+1, strict); err != nil {
				return err
			}
		}
	}
	want := json.Delim('}')
	if opening == '[' {
		want = ']'
	}
	if token, err := reader.Token(); err != nil || token != want {
		return problem(api.CodeIntegrity, "Codex JSON object or array is incomplete")
	}
	return nil
}

// Match api's UTF-16 escape rule for vendor objects up to MaxObjectBytes;
// DecodeObject itself is correctly restricted to the smaller RPC frame bound.
func validSurrogates(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		code, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
		if code < 0xd800 || code > 0xdbff {
			continue
		}
		if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}

// Proof is an internal installed-artifact receipt, not an RPC or a lane claim.
// The composition root verifies its review provenance before supplying its ref.
type compatibilityProof struct {
	Schema         string         `json:"schema"`
	AdapterVersion string         `json:"adapter_version"`
	Platform       string         `json:"platform"`
	Kind           string         `json:"kind"`
	Executable     api.Executable `json:"executable"`
	SelfHelper     api.Executable `json:"self_helper"`
	Observations   []api.BlobRef  `json:"observations"`
	Limits         []limitFixture `json:"limits"`
	Efforts        []string       `json:"efforts"`
}

type limitFixture struct {
	Kind    string      `json:"kind"`
	Capture api.BlobRef `json:"capture"`
}

func (s *Service) compatibility(ctx context.Context, reference api.BlobRef, kind string) error {
	_, err := s.loadCompatibility(ctx, reference, kind)
	return err
}

func (s *Service) loadCompatibility(ctx context.Context, reference api.BlobRef, kind string) (compatibilityProof, error) {
	var empty compatibilityProof
	if reference.ID == "" {
		return empty, api.NotImplemented("lb-v2-codex", "pinned Codex "+kind+" compatibility")
	}
	data, err := s.readBlob(ctx, reference)
	if err != nil {
		return empty, err
	}
	var proof compatibilityProof
	if decode(data, &proof) != nil || proof.Schema != "laneboss.codex-proof.v1" ||
		proof.AdapterVersion != AdapterVersion || proof.Platform != runtime.GOOS || proof.Kind != kind ||
		proof.Executable != s.deps.Runtime.Executable || proof.SelfHelper != s.deps.Runtime.SelfHelper || len(proof.Observations) == 0 {
		return empty, problem(api.CodeUnsupported, "Codex compatibility receipt does not bind this runtime and mode")
	}
	for _, observation := range proof.Observations {
		if !blob(observation) || observation.Bytes == 0 {
			return empty, problem(api.CodeIntegrity, "Codex compatibility receipt lacks retained observations")
		}
		if _, err := s.readBlob(ctx, observation); err != nil {
			return empty, err
		}
	}
	return proof, nil
}
