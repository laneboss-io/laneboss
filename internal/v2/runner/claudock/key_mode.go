package claudock

import (
	"encoding/json"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
)

// Bind a new home's authentication mode before publishing a launch. A mode
// cannot be changed after a session or an earlier mode has been retained.
func (h *Home) pinMode(mode string) error {
	if mode != "claudock-headless" && mode != "claude-api-key" {
		return failure(api.CodeForbidden, "private home credential mode is unsupported")
	}
	root, err := h.open()
	if err != nil {
		return err
	}
	defer root.Close()
	return h.records.transaction(h.key, func(record *homeRecord) error {
		if record.Mode != "" {
			if record.Mode != mode {
				return failure(api.CodeIntegrity, "private profile kind differs from the retained slot mode")
			}
			return nil
		}
		if mode == "claudock-headless" {
			record.Mode = mode
			return nil
		}
		if record.Session.ID != "" || len(record.Launches) != 0 {
			return failure(api.CodeIntegrity, "API key mode requires a new private session")
		}
		var registry registryProjection
		if decodeExact(record.Registry, &registry) != nil || registry.Version != 1 || len(registry.Profiles) != 1 {
			return failure(api.CodeIntegrity, "API key mode requires the original private registry")
		}
		id, err := newUUID()
		if err != nil {
			return err
		}
		registry.Version = 2
		registry.Profiles = append(registry.Profiles, registryProfile{Command: "claude-" + KeyProfile,
			ConfigDirectory: VendorDirectory, RegistryID: id, AuthKind: "apiKey", Managed: true})
		data, err := json.Marshal(registry)
		if err != nil {
			return failure(api.CodeIntegrity, "private API key registry cannot be encoded")
		}
		const path = ".config/claudock/profiles.json"
		if err := replacePrivate(root, ".config/claudock", path, data, 0400); err != nil {
			return err
		}
		owner, ok := h.identity.Sys().(*syscall.Stat_t)
		if !ok {
			return ownedError(ErrOwnedMode)
		}
		if err := root.Chown(path, int(owner.Uid), int(owner.Gid)); err != nil {
			return ownedError(ErrOwnedMode)
		}
		record.Registry, record.Generated[path], record.Mode = data, contentDigest(data), mode
		return nil
	}, nil)
}
