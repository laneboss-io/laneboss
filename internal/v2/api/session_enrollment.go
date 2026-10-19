package api

import (
	"path"
	"strings"
	"unicode/utf8"
)

// RuntimeSessionExecutable checks metadata from protected launch enrollment
// against its pinned runtime manifest. It supplies no default vendor/version.
// A wrapper with a separately enrolled Claude must select that exact file as
// its history owner; a direct runner selects its own installed file.
func RuntimeSessionExecutable(enrollment LaunchRuntime, manifest RuntimeManifest) (Executable, error) {
	refused := func() (Executable, error) {
		return Executable{}, &Error{Code: CodePrerequisite, Owner: "lb-v2-admin",
			Message: "installed runtime session executable is missing or mismatched",
			Instead: "Enroll the exact history-owning executable and version with the pinned runtime before launching."}
	}
	vendor := enrollment.SessionExecutable
	if !launchExecutable(vendor) || !utf8.ValidString(vendor.Version) ||
		strings.IndexFunc(vendor.Version, func(r rune) bool { return r <= 32 || r == 127 }) >= 0 ||
		manifest.Schema != "laneboss.runtime.v2" || !launchGeneration(manifest.Generation) {
		return refused()
	}
	seen, paths := map[ID]bool{}, map[string]bool{}
	roles := map[string]RuntimeObject{}
	matched, wrapper := false, false
	for _, object := range manifest.Objects {
		key := string(object.RootID) + "/" + object.RelativePath
		if !launchID(object.ID) || seen[object.ID] || paths[key] || !launchID(object.RootID) ||
			object.RelativePath == "." || object.RelativePath == "" || path.IsAbs(object.RelativePath) ||
			path.Clean(object.RelativePath) != object.RelativePath || object.RelativePath == ".." || strings.HasPrefix(object.RelativePath, "../") {
			return refused()
		}
		seen[object.ID], paths[key] = true, true
		if object.Role == "claudock" || object.Role == "claude" {
			if roles[object.Role].ID != "" || object.ID != ID(object.Role) || object.RelativePath != object.Role || object.Mode != 0555 {
				return refused()
			}
			roles[object.Role] = object
		}
		pinned := object.Mode == 0555 && object.Content.Class == "artifact" &&
			object.Content.Bytes > 0 && object.Content.Bytes <= MaxVendorBytes && bindingDigest.MatchString(string(object.Content.SHA256))
		matched = matched || pinned && object.ID == vendor.ID && object.Content.SHA256 == vendor.SHA256
		wrapper = wrapper || pinned && object.ID == enrollment.Executable.ID && object.Content.SHA256 == enrollment.Executable.SHA256
	}
	if !matched || !wrapper {
		return refused()
	}
	if len(roles) != 0 {
		if len(roles) != 2 || enrollment.Driver != DriverClaudock || enrollment.Executable.ID != roles["claudock"].ID ||
			vendor.ID != roles["claude"].ID || vendor.SHA256 != roles["claude"].Content.SHA256 {
			return refused()
		}
	} else if vendor.ID != enrollment.Executable.ID || vendor.SHA256 != enrollment.Executable.SHA256 {
		return refused()
	}
	return vendor, nil
}
