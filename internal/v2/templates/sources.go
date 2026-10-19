package templates

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"

	"laneboss.io/laneboss/internal/v2/api"
)

const (
	OrgTemplatePath = ".laneboss/shared/templates/default.md"
	OrgDriversPath  = ".laneboss/shared/templates/drivers.toml"
	WorkflowPath    = ".laneboss/shared/workflow.toml"
	MaxSourceBytes  = 2 * 1024 * 1024
	maxGeneration   = 1<<53 - 1
)

// Source is an in-memory renderer input, not a new wire or storage contract.
// Its bytes must be obtained from the approved service snapshot, never a client
// path. Resolve checks the supplied immutable reference before using the bytes.
type Source struct {
	Ref   api.SourceRef
	Bytes []byte
}

// Layers holds only the org pair and the selected role pair. A wholly absent
// local pair inherits org; a partial or invalid local pair is an error.
type Layers struct {
	Generation api.Generation
	Org        Source
	OrgDrivers Source
	Local      *Source
	Drivers    *Source
}

// Resolved cannot be constructed outside this package with unchecked content.
// It owns copies so a caller cannot change a validated source after resolution.
type Resolved struct {
	context    api.RoleContext
	generation api.Generation
	selected   api.SourceRef
	body       []byte
	drivers    []api.Driver
	sources    []Source
}

var safeID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var safeDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func problem(code api.ErrorCode, message, instead string) *api.Error {
	return &api.Error{Code: code, Message: message, Instead: instead, Owner: "lb-v2-templates"}
}

func invalid(message string) *api.Error {
	return problem(api.CodeInvalid, message, "Correct the file input and use the approved org source generation.")
}

func integrity(message string) *api.Error {
	return problem(api.CodeIntegrity, message, "Preserve inputs and receipts; ask the supervisor to verify the approved source snapshot.")
}

func checkContext(context api.RoleContext) error {
	if context.Level < 3 || context.Level > 6 {
		return invalid("template level must be in L3 through L6")
	}
	if !utf8.ValidString(context.Role) || len(context.Role) == 0 ||
		utf8.RuneCountInString(context.Role) > 128 || strings.TrimSpace(context.Role) != context.Role ||
		context.Role == "." || context.Role == ".." || strings.ContainsAny(context.Role, "/\\") ||
		strings.IndexFunc(context.Role, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return invalid("template role must be one nonempty safe filename")
	}
	if context.InstanceID != "" && !safeID.MatchString(string(context.InstanceID)) {
		return invalid("invalid template instance identifier")
	}
	return nil
}

func hash(data []byte) api.Digest {
	return api.Digest(fmt.Sprintf("%x", sha256.Sum256(data)))
}

func checkSource(source Source, expectedPath string, generation api.Generation) error {
	if !safeID.MatchString(string(source.Ref.ID)) || !safeDigest.MatchString(string(source.Ref.SHA256)) {
		return invalid("invalid template source reference")
	}
	if source.Ref.Generation == 0 || source.Ref.Generation > maxGeneration ||
		source.Ref.Generation != generation {
		return problem(api.CodeConflict, "template source generation differs from the approved snapshot",
			"Resolve the current approved generation; do not reuse a stale template reference.")
	}
	if source.Ref.Path != expectedPath || path.Clean(source.Ref.Path) != source.Ref.Path {
		return problem(api.CodeForbidden, "template source does not belong to the selected layer and role",
			"Select the approved org default or the exact level and role source.")
	}
	if len(source.Bytes) == 0 || len(source.Bytes) > MaxSourceBytes || !utf8.Valid(source.Bytes) || bytes.ContainsRune(source.Bytes, 0) {
		return invalid("template source must be nonempty UTF-8 within 2 MiB")
	}
	if hash(source.Bytes) != source.Ref.SHA256 {
		return integrity("template source bytes differ from their retained digest")
	}
	return nil
}

func checkBody(data []byte) error {
	// This validation view does not alter the retained or rendered source bytes.
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	if strings.HasPrefix(strings.TrimSpace(text), "---\n") {
		return invalid("template source must not contain front matter")
	}
	for _, heading := range []string{"Scope", "Responsibilities", "Deliverable", "Must not"} {
		pattern := `(?m)^#{1,6}[ \t]+` + heading + `[ \t]*#*[ \t]*$`
		if !regexp.MustCompile(pattern).MatchString(text) {
			return invalid("template source is missing a required role section")
		}
	}
	return nil
}

func parseDrivers(data []byte) ([]api.Driver, error) {
	var document struct {
		Drivers []string `toml:"drivers"`
	}
	metadata, err := toml.Decode(string(data), &document)
	if err != nil || len(metadata.Undecoded()) != 0 || len(document.Drivers) < 1 || len(document.Drivers) > 2 {
		return nil, invalid("driver source must contain only one or two distinct primary drivers")
	}
	result := make([]api.Driver, 0, len(document.Drivers))
	for _, name := range document.Drivers {
		driver := api.Driver(name)
		if driver != api.DriverClaudock && driver != api.DriverCodex {
			return nil, problem(api.CodeForbidden, "driver source contains an unsupported primary agent driver",
				"Use claudock-cli or codex; an ordinary tool is not an agent-driver entry.")
		}
		if slices.Contains(result, driver) {
			return nil, invalid("driver source contains a duplicate driver")
		}
		result = append(result, driver)
	}
	return result, nil
}

func copySource(source Source) Source {
	return Source{Ref: source.Ref, Bytes: bytes.Clone(source.Bytes)}
}

// Resolve selects the exact local role pair, or the explicit org default when
// the entire local pair is absent. Templates are text, not executable Go
// templates. Resolution performs no I/O, command matching or authority grant.
func Resolve(context api.RoleContext, layers Layers) (*Resolved, error) {
	if err := checkContext(context); err != nil {
		return nil, err
	}
	if layers.Generation == 0 || layers.Generation > maxGeneration {
		return nil, invalid("an approved template generation is required")
	}
	if err := checkSource(layers.Org, OrgTemplatePath, layers.Generation); err != nil {
		return nil, err
	}
	if err := checkBody(layers.Org.Bytes); err != nil {
		return nil, err
	}
	if err := checkSource(layers.OrgDrivers, OrgDriversPath, layers.Generation); err != nil {
		return nil, err
	}
	drivers, err := parseDrivers(layers.OrgDrivers.Bytes)
	if err != nil {
		return nil, err
	}
	selected := layers.Org
	sources := []Source{layers.Org, layers.OrgDrivers}
	if (layers.Local == nil) != (layers.Drivers == nil) {
		return nil, invalid("local role source and driver source must be a complete pair")
	}
	if layers.Local != nil {
		base := fmt.Sprintf(".laneboss/L%d/roles/%s", context.Level, context.Role)
		if err := checkSource(*layers.Local, base+".md", layers.Generation); err != nil {
			return nil, err
		}
		if err := checkBody(layers.Local.Bytes); err != nil {
			return nil, err
		}
		if err := checkSource(*layers.Drivers, base+".toml", layers.Generation); err != nil {
			return nil, err
		}
		localDrivers, err := parseDrivers(layers.Drivers.Bytes)
		if err != nil {
			return nil, err
		}
		for _, driver := range localDrivers {
			if !slices.Contains(drivers, driver) {
				return nil, problem(api.CodeForbidden, "local primary drivers exceed the org catalog",
					"Propose an exact org change through L6 and direct human approval.")
			}
		}
		selected, drivers = *layers.Local, localDrivers
		sources = append(sources, *layers.Local, *layers.Drivers)
	}
	seen := map[api.ID]bool{}
	for index, source := range sources {
		if seen[source.Ref.ID] {
			return nil, invalid("template source identifiers must be distinct")
		}
		seen[source.Ref.ID] = true
		sources[index] = copySource(source)
	}
	return &Resolved{
		context: context, generation: layers.Generation, selected: selected.Ref,
		body: bytes.Clone(selected.Bytes), drivers: slices.Clone(drivers), sources: sources,
	}, nil
}

// RetainedSources returns independent copies for an approved-source archive.
// The caller still has to persist them using the service-owned object store.
func (r *Resolved) RetainedSources() []Source {
	if r == nil {
		return nil
	}
	result := make([]Source, len(r.sources))
	for index, source := range r.sources {
		result[index] = copySource(source)
	}
	return result
}
