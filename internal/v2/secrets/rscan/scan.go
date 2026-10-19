package rscan

import (
	"bytes"
	"context"
	"io"
	"os"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

// The closed inventory and its spelling are shared by the release journal and
// status. Finding paths are separate, redacted diagnostics; source IDs, errors
// and material never enter this inventory.
var reusePlaces = [...]string{
	"lane-home", "claude-config", "claudock-registry", "credential-store",
	"helper-state", "evidence", "service-journal", "helper-journal", "credential-journal",
}

func APIKeyScanPlaces() [9]string { return reusePlaces }

type APIKeyPlaceResult struct {
	Present        bool   `json:"present"`
	Key            bool   `json:"key"`
	Last8          bool   `json:"last8"`
	Unreadable     bool   `json:"unreadable"`
	Files          uint64 `json:"files"`
	Links          uint64 `json:"links"`
	Path           string `json:"path,omitempty"`
	UnreadablePath string `json:"unreadable_path,omitempty"`
}

// An array prevents a producer from omitting an unreadable place. The zero
// value is NOT a clean observation: required places must also be present.
type APIKeyScanResult [9]APIKeyPlaceResult

func (r APIKeyScanResult) Clean() bool {
	for i, place := range r {
		if place.Key || place.Last8 || place.Unreadable || (i == 0 || i >= 4) && !place.Present {
			return false
		}
	}
	return true
}

func (r APIKeyScanResult) FirstHit() string {
	for i, place := range r {
		if place.Key || place.Last8 || place.Unreadable || (i == 0 || i >= 4) && !place.Present {
			return reusePlaces[i]
		}
	}
	return ""
}

// Line retains the fixed verdict tokens and appends finding paths, quoted so
// a filename cannot inject journal lines. Producers redact paths while they
// hold the key; native/broker boundaries repeat that redaction before retention.
func (r APIKeyScanResult) Line() string {
	var line strings.Builder
	line.WriteString("api_key_release")
	for i, place := range r {
		line.WriteByte(' ')
		line.WriteString(reusePlaces[i])
		line.WriteByte('=')
		switch {
		case place.Key || place.Last8 || place.Unreadable || (i == 0 || i >= 4) && !place.Present:
			line.WriteString("hit")
		default:
			line.WriteString("clean")
		}
	}
	for i, place := range r {
		if place.Path != "" {
			line.WriteString(" " + reusePlaces[i] + ".path=" + strconv.Quote(place.Path))
		}
		if place.UnreadablePath != "" {
			line.WriteString(" " + reusePlaces[i] + ".unreadable_path=" + strconv.Quote(place.UnreadablePath))
		}
	}
	line.WriteByte('\n')
	return line.String()
}

// Redacted is also applied to results received from private native adapters.
// A key-bearing filename is an exposure, never permission to log its bytes.
func (r APIKeyScanResult) Redacted(key []byte) APIKeyScanResult {
	if len(key) < 8 || len(key) > 4096 {
		return UnreadableAPIKeyScan()
	}
	for i := range r {
		r[i].Path = redactReusePath(r[i].Path, key)
		r[i].UnreadablePath = redactReusePath(r[i].UnreadablePath, key)
	}
	return r
}

func redactReusePath(path string, key []byte) string {
	path = strings.ReplaceAll(path, string(key), "[withheld]")
	path = strings.ReplaceAll(path, string(key[len(key)-8:]), "[withheld]")
	// Replacement text or a replacement boundary must not recreate a needle.
	if strings.Contains(path, string(key)) || strings.Contains(path, string(key[len(key)-8:])) {
		return "<path>"
	}
	return path
}

func UnreadableAPIKeyScan() APIKeyScanResult {
	var result APIKeyScanResult
	for i := range result {
		result[i].Unreadable = true
	}
	return result
}

// This is an installed, in-process port, never a lane RPC. Native adapters must
// retain their authenticated home identity and consume material privately.
type APIKeyReleaseScanner interface {
	ScanAPIKeyRelease(context.Context, api.CredentialProjectionAuthority, api.SecretMaterial) (APIKeyScanResult, error)
}

type APIKeyReleaseScanFunc func(context.Context, api.CredentialProjectionAuthority, api.SecretMaterial) (APIKeyScanResult, error)

func (f APIKeyReleaseScanFunc) ScanAPIKeyRelease(ctx context.Context, a api.CredentialProjectionAuthority, material api.SecretMaterial) (APIKeyScanResult, error) {
	return f(ctx, a, material)
}

// Inputs come from the installed helper's retained storage inventory, not from
// the lane. HomeIdentity is the native root observed at allocation. Journal
// readers must report query/exit failures from Close as well as Read.
type APIKeyScanInputs struct {
	Home         string
	HomeIdentity os.FileInfo
	HelperState  string
	Evidence     string
	Journal      func(context.Context, string) (io.ReadCloser, error)
}

// ScanAPIKeyReleaseInputs promotes the R3 file/journal scanners to production.
// Like api_key_canary.py, it checks names, link text and a streaming overlap of
// regular bytes for both needles, and never follows links to find more bytes.
func ScanAPIKeyReleaseInputs(ctx context.Context, material api.SecretMaterial, inputs APIKeyScanInputs) APIKeyScanResult {
	key := material.Bytes
	if len(key) < 8 || len(key) > 4096 {
		return UnreadableAPIKeyScan()
	}
	var result APIKeyScanResult
	result[0] = scanReuseTree(ctx, key, inputs.Home, true, inputs.HomeIdentity)
	if inputs.HomeIdentity == nil {
		result[0].Unreadable = true
		result[0].UnreadablePath = redactReusePath(inputs.Home, key)
	}
	for i, name := range []string{".claude", ".config/claudock/profiles.json", ".config/claudock/credential-store.json"} {
		result[i+1] = scanReuseChild(ctx, key, inputs.Home, name)
	}
	result[4] = scanReuseTree(ctx, key, inputs.HelperState, true, nil)
	result[5] = scanReuseTree(ctx, key, inputs.Evidence, true, nil)
	for i, role := range []string{"service", "helper", "credential"} {
		place := &result[6+i]
		if inputs.Journal == nil || ctx.Err() != nil {
			place.Unreadable = true
			continue
		}
		stream, err := inputs.Journal(ctx, role)
		if err != nil || stream == nil {
			if stream != nil {
				stream.Close()
			}
			place.Unreadable = true
			continue
		}
		place.Present = true
		n, nonempty, readErr := scanReuseReader(ctx, stream, key, "", place)
		closeErr := stream.Close()
		place.Files = 1
		place.Unreadable = readErr != nil || closeErr != nil || n == 0 || !nonempty
	}
	return result
}

func matchReuse(data, key []byte, path string, result *APIKeyPlaceResult) {
	full, tail := bytes.Contains(data, key), bytes.Contains(data, key[len(key)-8:])
	result.Key = result.Key || full
	result.Last8 = result.Last8 || tail
	if (full || tail) && path != "" && result.Path == "" {
		result.Path = redactReusePath(path, key)
	}
}

func scanReuseReader(ctx context.Context, input io.Reader, key []byte, path string, result *APIKeyPlaceResult) (int64, bool, error) {
	buffer := make([]byte, 64*1024+len(key))
	defer clear(buffer)
	var total int64
	overlap, emptyReads := 0, 0
	nonempty := false
	for {
		if err := ctx.Err(); err != nil {
			return total, nonempty, err
		}
		n, err := input.Read(buffer[overlap:])
		if n > 0 {
			emptyReads = 0
			total += int64(n)
			data := buffer[:overlap+n]
			nonempty = nonempty || len(bytes.TrimSpace(data)) != 0
			matchReuse(data, key, path, result)
			overlap = min(len(key)-1, len(data))
			copy(buffer, data[len(data)-overlap:])
		} else {
			emptyReads++
		}
		if err == io.EOF {
			return total, nonempty, nil
		}
		if err != nil {
			return total, nonempty, err
		}
		if emptyReads >= 100 || total > 64<<30 {
			return total, nonempty, io.ErrNoProgress
		}
	}
}
