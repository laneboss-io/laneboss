package wire

import (
	"encoding/json"
	"math/bits"
	"strings"

	"laneboss.io/laneboss/internal/typesafe"
	"laneboss.io/laneboss/internal/v2/api"
)

const (
	MaxScreenInputBytes = api.MaxFrameBytes
	MaxScreenWorkBytes  = 8 << 20
	MaxScreenDepth      = 32
	MaxScreenNodes      = 65536 // Per pass; request screening uses at most two passes.
	// Keep a complete view, including every variable-length signature component
	// and separator. A view that cannot fit is withheld, never rolled forward.
	ScreenWindowBytes = MaxScreenInputBytes
	maxScreenKeyBytes = 8192
	ScreenCapReason   = "credential screening cap reached"
)

// Work units charge inspected/copied/decoded bytes and radix bucket steps.
// One complete fixed pattern set is charged once per string/view; its RE2
// calls are each linear. All additional inspections share this single budget.
type screenBudget struct {
	left        int
	nodes       int
	exhausted   bool
	key         string
	views       [6]fragmentView
	joins       bool
	keyOnly     bool
	execution   bool
	decodedOnly bool
}

// Locations identify service-authored exclusions, never caller field grants.
// Unknown locations and embedded documents always keep caller joins enabled.
type screenPath uint8

const (
	dataPath screenPath = iota
	requestPath
	statePath
	commandsPath
	commandPath
	contextPath
	targetPath
	rolePath
	rulesPath
	rulePath
	decisionsPath
	decisionPath
	decisionSourcePath
	decisionAuthorityPath
	decisionAppliesToPath
	metadataListPath
	questionsPath
	questionPath
	criteriaPath
)

type fragmentView struct {
	buffer []byte
	window int
	spaced bool
	seen   bool
}

func newScreen(key string) *screenBudget {
	s := &screenBudget{left: MaxScreenWorkBytes, key: key, joins: true}
	if len(key) > maxScreenKeyBytes {
		s.exhausted = true
		return s
	}
	for i := range s.views {
		s.views[i] = fragmentView{window: ScreenWindowBytes, spaced: i%2 != 0}
	}
	return s
}

func (s *screenBudget) spend(n int) bool {
	if s.exhausted || n < 0 || n > s.left {
		s.exhausted = true
		return false
	}
	s.left -= n
	return true
}

func (s *screenBudget) node() bool {
	if s.nodes >= MaxScreenNodes {
		s.exhausted = true
		return false
	}
	s.nodes++
	return true
}

func (s *screenBudget) text(text string) bool {
	if len(text) > MaxScreenInputBytes {
		s.exhausted = true
		return true
	}
	if !s.spend(len(text)) || s.key != "" && strings.Contains(text, s.key) {
		return true
	}
	hit, capped := screenText(text, s.spend)
	s.exhausted = s.exhausted || capped
	return hit
}

func (s *screenBudget) fragments(text []byte) bool {
	if !s.spend(len(text)) {
		return true
	}
	value := string(text)
	return s.key != "" && strings.Contains(value, s.key) || !s.keyOnly && credentialText(value)
}

// Six complete views preserve the fix-1 joins without assuming a maximum
// credential/separator length. Each view is capped at 1 MiB and scanned once
// at finish; no growing-prefix scans or discarded windows are permitted.
func (s *screenBudget) appendView(view *fragmentView, text string) bool {
	if view.spaced && view.seen && s.appendBytes(view, " ") {
		return true
	}
	view.seen = true
	return s.appendBytes(view, text)
}

func (s *screenBudget) appendBytes(view *fragmentView, text string) bool {
	if len(text) > view.window-len(view.buffer) {
		s.exhausted = true
		return true
	}
	if !s.spend(len(text)) {
		return true
	}
	needed := len(view.buffer) + len(text)
	if needed > cap(view.buffer) {
		// Geometric growth bounds total copies by twice the final size. Charge
		// them explicitly and clamp the allocation itself to the view cap.
		if !s.spend(len(view.buffer)) {
			return true
		}
		// Round the first large fragment too: a following five-byte CWD must
		// not force an immediate whole-buffer copy. Bounds and copy charges
		// are unchanged, including a non-power-of-two view window.
		capacity := 1 << bits.Len(uint(max(needed, 2*cap(view.buffer))-1))
		next := make([]byte, len(view.buffer), min(view.window, capacity))
		copy(next, view.buffer)
		view.buffer = next
	}
	view.buffer = append(view.buffer, text...)
	return false
}

func (s *screenBudget) feed(text string, name bool) bool {
	start := 2
	if name {
		start = 0
	}
	return s.appendView(&s.views[start], text) || s.appendView(&s.views[start+1], text) ||
		s.appendView(&s.views[4], text) || s.appendView(&s.views[5], text)
}

func (s *screenBudget) finish() bool {
	if s.exhausted {
		return true
	}
	if !s.joins {
		return false
	}
	for i := range s.views {
		if s.fragments(s.views[i].buffer) {
			return true
		}
	}
	return false
}

// A scope owns its views, but shares every byte/node/depth cap with the frame.
// A scoped view is collected once and scanned once; no prefix or pair rescans.
func (s *screenBudget) scope(value any, depth int) bool {
	previous, joins, keyOnly := s.views, s.joins, s.keyOnly
	execution, decodedOnly := s.execution, s.decodedOnly
	for i := range s.views {
		s.views[i] = fragmentView{window: ScreenWindowBytes, spaced: i%2 != 0}
	}
	s.joins, s.keyOnly = true, false
	s.execution, s.decodedOnly = false, false
	hit := s.walk(value, depth) || s.finish()
	s.views, s.joins, s.keyOnly = previous, joins, keyOnly
	s.execution, s.decodedOnly = execution, decodedOnly
	return hit
}

func (s *screenBudget) walk(value any, depth int) bool {
	return s.walkAt(value, depth, dataPath)
}

func (s *screenBudget) walkAt(value any, depth int, at screenPath) bool {
	if depth > MaxScreenDepth || !s.node() {
		s.exhausted = true
		return true
	}
	switch value := value.(type) {
	case string:
		if s.text(value) {
			return true
		}
		text := strings.TrimSpace(value)
		if len(text) > 0 && strings.ContainsRune("{[\"", rune(text[0])) {
			if !s.spend(len(text)) {
				return true
			}
			if json.Valid([]byte(text)) {
				if s.joins && !s.decodedOnly && s.feed(value, false) {
					return true
				}
				if !s.spend(2*len(text) + 10) {
					return true
				}
				decoded, err := typesafe.Decode([]byte(`{"value":` + text + `}`))
				if err != nil {
					return true
				}
				if !s.joins {
					return s.scope(decoded["value"], depth+1)
				}
				if s.keyOnly && s.scope(decoded["value"], depth+1) {
					return true
				}
				if s.walk(decoded["value"], depth+1) {
					return true
				}
				return false
			}
		}
		return s.joins && s.feed(value, false)
	case map[string]any:
		keys := make([]string, 0, min(len(value), MaxScreenNodes))
		for name := range value {
			if !s.node() || !s.spend(len(name)+1) {
				return true
			}
			keys = append(keys, name)
		}
		if !s.orderKeys(keys) {
			return true
		}
		if s.execution && at == commandPath {
			if !s.spend(len(keys) + 6) {
				return true
			}
			ordered := make([]string, 0, len(keys))
			for _, name := range []string{"cwd", "command", "argv", "declared_paths", "tool", "raw_sha256"} {
				if _, present := value[name]; present {
					ordered = append(ordered, name)
				}
			}
			for _, name := range keys {
				switch name {
				case "cwd", "command", "argv", "declared_paths", "tool", "raw_sha256":
				default:
					ordered = append(ordered, name)
				}
			}
			keys = ordered
		}
		for _, name := range keys {
			child := value[name]
			next, schema, metadata := requestField(at, name)
			if s.text(name) || s.joins && !schema && s.feed(name, true) {
				return true
			}
			if text, ok := child.(string); ok && sensitiveName.MatchString(name) {
				if !s.spend(len(text)) || literalQuoted(text) {
					return true
				}
			}
			// Exclusions are scalar leaves. An unexpected container at an
			// approved path is caller data, not an exempt subtree.
			previous := s.joins
			if _, scalar := child.(string); scalar && metadata {
				s.joins = false
			}
			hit := s.walkAt(child, depth+1, next)
			s.joins = previous
			if hit {
				return true
			}
		}
	case []any:
		for _, child := range value {
			next := dataPath
			if at == commandsPath {
				next = commandPath
			} else if at == rulesPath {
				next = rulePath
			} else if at == decisionsPath {
				next = decisionPath
			}
			// Only direct string members of an approved metadata list are
			// excluded. Unexpected containers retain the caller-data default.
			previous := s.joins
			if _, scalar := child.(string); scalar && at == metadataListPath {
				s.joins = false
			}
			hit := s.walkAt(child, depth+1, next)
			s.joins = previous
			if hit {
				return true
			}
		}
	}
	return false
}

// MSD byte radix order keeps the previous deterministic key order without
// comparing shared prefixes O(log K) times. Each participating key byte is
// read a fixed number of times; bucket steps and pointer copies are budgeted.
func (s *screenBudget) orderKeys(keys []string) bool {
	type group struct{ lo, hi, at int }
	if len(keys) < 2 {
		return true
	}
	aux := make([]string, len(keys))
	groups := []group{{hi: len(keys)}}
	for len(groups) > 0 {
		g := groups[len(groups)-1]
		groups = groups[:len(groups)-1]
		if !s.spend(257 + 3*(g.hi-g.lo)) {
			return false
		}
		var counts, starts, next [257]int
		bucket := func(key string) int {
			if g.at >= len(key) {
				return 0
			}
			return int(key[g.at]) + 1
		}
		for _, key := range keys[g.lo:g.hi] {
			counts[bucket(key)]++
		}
		position := g.lo
		for i, count := range counts {
			starts[i], next[i] = position, position
			position += count
		}
		for _, key := range keys[g.lo:g.hi] {
			b := bucket(key)
			aux[next[b]] = key
			next[b]++
		}
		copy(keys[g.lo:g.hi], aux[g.lo:g.hi])
		for i := 1; i < len(counts); i++ {
			if counts[i] > 1 {
				groups = append(groups, group{starts[i], starts[i] + counts[i], g.at + 1})
			}
		}
	}
	return true
}

// Sensitive withholds on a signature, exact key echo or any resource cap.
// Every complete string and capped complete cross-field view is inspected.
// These additional views never replace the transmitted bytes.
func Sensitive(value any, key string) bool {
	hit, _ := screenResult(value, key)
	return hit
}

func screenResult(value any, key string) (bool, bool) {
	s := newScreen(key)
	hit := s.exhausted || s.walk(value, 0) || s.finish()
	return hit, s.exhausted
}

// SensitiveStrings screens complete strings/keys and embedded JSON without
// manufacturing tokens by concatenating unrelated structured metadata fields.
func SensitiveStrings(value any, key string) bool {
	s := newScreen(key)
	s.joins = false
	return s.exhausted || s.walk(value, 0) || s.finish()
}

// Provider protocol fields are separate metadata, but an exact credential echo
// must still be caught if the provider splits that known key between fields.
func SensitiveResponse(value any, key string) bool {
	s := newScreen(key)
	s.joins, s.keyOnly = key != "", true
	return s.exhausted || s.walk(value, 0) || s.finish()
}

// RequestSensitive is also used when independently reading retained requests.
func RequestSensitive(root map[string]any, key string) bool {
	hit, _ := requestScreenResult(root, key)
	return hit
}

func requestScreenResult(root map[string]any, key string) (bool, bool) {
	_, model := root["model"].(string)
	_, questions := root["questions"].(map[string]any)
	stateValue, state := root["state"].(map[string]any)
	if !model || !questions || !state {
		// Generic JSON text has no trusted schema fields. Its ordered parts
		// remain one data scope, including all original split canaries.
		return screenResult(root, key)
	}
	commands, valid := stateValue["commands"].([]any)
	if !valid || len(commands) > 1 {
		// Payload emits zero or one command. Nonconforming documents retain
		// the conservative generic screen, without any metadata exclusions.
		return screenResult(root, key)
	}
	s := newScreen(key)
	hit := s.exhausted || s.walkAt(root, 0, requestPath) || s.finish()
	if !hit {
		// A second fixed pass makes embedded JSON transparent to caller
		// adjacency and orders command fields cwd -> command -> argv -> paths.
		// The first pass preserves the frozen raw/decoded document order.
		for i := range s.views {
			s.views[i] = fragmentView{window: ScreenWindowBytes, spaced: i%2 != 0}
		}
		// Each pass may visit 65,536 value/key nodes, including embedded
		// scopes. Do not reset the shared byte/work budget or exhaustion.
		s.nodes = 0
		s.execution, s.decodedOnly = true, true
		hit = s.walkAt(root, 0, requestPath) || s.finish()
	}
	return hit, s.exhausted
}
