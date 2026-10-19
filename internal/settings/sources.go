package settings

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/instancename"
)

// CheckSources validates optional org and instance files, including files that
// no current lane has selected. A malformed higher layer never goes unnoticed.
func CheckSources(root string, screen func([]byte) error) error {
	check := func(relative, scope string) error {
		data, err := Read(root, relative)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return errors.New("settings source cannot be read safely: " + relative)
		}
		_, err = ParseFile(data, filepath.Join(root, relative), scope, "", screen)
		if err != nil {
			return fmt.Errorf("%s: %w", relative, err)
		}
		return nil
	}
	if err := check(".laneboss/settings.toml", "org"); err != nil {
		return err
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return errors.New("settings org cannot be opened")
	}
	defer r.Close()
	dir, err := r.Open(".laneboss/instances")
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("settings instances cannot be read")
	}
	defer dir.Close()
	items, err := dir.ReadDir(-1)
	if err != nil || len(items) > 4096 {
		return errors.New("settings instances exceed the readable entry limit")
	}
	for _, item := range items {
		if item.Type()&os.ModeSymlink != 0 {
			return errors.New("settings instance directories must not be links")
		}
		if item.IsDir() {
			if !instancename.Valid(item.Name()) {
				return errors.New("settings instance directory name is invalid")
			}
			if err := check(filepath.Join(".laneboss", "instances", item.Name(), "settings.toml"), "instance"); err != nil {
				return err
			}
		}
	}
	return nil
}

func SourceHash(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

// Again discards the old file-derived values, retains explicit lane overrides,
// and reads current org/role/instance files. Previous run identity is a fallback
// only for settings that no current layer defines.
func Again(root string, previous map[string]any, changes map[string]any, screen func([]byte) error) (*Snapshot, error) {
	overrides := map[string]any{}
	instance := ""
	var delegation *Limits
	if value, exists := previous["settings"]; exists {
		old, err := Decode(value)
		if err != nil {
			return nil, err
		}
		for key, value := range old.Overrides {
			overrides[key] = value
		}
		instance = old.Instance
		delegation = old.Delegation
	}
	for key, value := range changes {
		if key != "account" {
			overrides[key] = value
		}
	}
	context, _ := previous["role_context"].(map[string]any)
	level, _ := Number(context["level"])
	role, _ := previous["role"].(string)
	s, err := Resolve(root, int(level), role, instance, overrides, screen)
	if err != nil {
		return nil, err
	}
	if account, requested := changes["account"]; requested {
		if err := s.RequestAccount(account); err != nil {
			return nil, err
		}
	}
	defaults := map[string]any{}
	for _, key := range []string{"runner", "model", "effort", "account", "budget_minutes"} {
		defaults[key] = previous[key]
	}
	s.Defaults(defaults, "previous run fallback")
	// Every run binds fresh limits from the recorded starter. The fault restores
	// the former first-start ceiling at the actual re-resolution boundary.
	if faults.Get("settings-frozen-delegation").Point != "" && delegation != nil {
		s.Delegation = delegation
		if err := faults.Reach("settings-frozen-delegation"); err != nil {
			return nil, err
		}
		if err := s.CheckDelegation(); err != nil {
			return nil, err
		}
	}
	if runner, ok := s.Values["runner"]; ok && runner != previous["runner"] {
		return nil, errors.New("resolved runner differs from the recorded runner; the human must start a new lane to change runners")
	}
	return s, nil
}
