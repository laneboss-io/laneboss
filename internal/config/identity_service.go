package config

import (
	"os"
	"path/filepath"
	"syscall"
)

const IdentityRuntimeRoot = "/var/run/laneboss"
const IdentityBindingRoot = "/etc/laneboss/identity"

const IdentityBindingUnavailable = "the configured identity service binding is unavailable"

func bindingUnavailable() error {
	return refused(IdentityBindingUnavailable + "\nInstead: have the administrator restore the configured service and its protected runtime binding; retain the persistent service selection and do not register through legacy files.")
}

func persistentBinding(name string) (bool, error) {
	path := filepath.Join(IdentityBindingRoot, name)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return true, bindingUnavailable()
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0644 {
		return true, bindingUnavailable()
	}
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		parent, err := os.Stat(directory)
		if err != nil || !parent.IsDir() || parent.Mode().Perm()&0022 != 0 {
			return true, bindingUnavailable()
		}
		stat, ok := parent.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return true, bindingUnavailable()
		}
		if filepath.Dir(directory) == directory {
			return true, nil
		}
	}
}

// IdentityService selects an explicitly configured service, or the installed
// persistent system binding. Volatile runtime directories never select legacy
// after a service stop; installed binding-only deployments require the marker.
// Only an absent table and absent persistent selection permit legacy mode.
// Invalid or partial input is an error with configured=true, never absence.
func IdentityService(c *Configuration) (string, bool, error) {
	if c == nil {
		return "", true, invalid("identity_service: the configuration is missing")
	}
	if err := CheckName(c.Name); err != nil {
		return "", true, err
	}
	value, present := c.Data["identity_service"]
	root := IdentityRuntimeRoot
	if present {
		if err := table(map[string]check{"runtime_root": absolutePath})(checker{"configuration"}, value, "identity_service"); err != nil {
			return "", true, err
		}
		if selected, exists := tableOf(value)["runtime_root"]; exists {
			root = selected.(string) // validated above, including nonempty/absolute
		}
	}
	installed, err := persistentBinding(c.Name)
	if err != nil {
		return "", true, err
	}
	global, globalError := os.Lstat(filepath.Join(IdentityRuntimeRoot, c.Name))
	if globalError != nil && !os.IsNotExist(globalError) {
		return "", true, bindingUnavailable()
	}
	if installed || globalError == nil {
		if !installed && !present {
			return "", true, refused("the identity service binding needs persistent configuration\nInstead: have the administrator add [identity_service] to protected config or install the root-owned persistent binding marker before registering.")
		}
		if globalError != nil || !global.IsDir() || global.Mode().Perm()&0500 != 0500 || global.Mode().Perm()&0022 != 0 {
			return "", true, bindingUnavailable()
		}
		return IdentityRuntimeRoot, true, nil
	}
	if present {
		binding, err := os.Lstat(filepath.Join(root, c.Name))
		if err != nil || !binding.IsDir() || binding.Mode().Perm()&0500 != 0500 || binding.Mode().Perm()&0022 != 0 {
			return "", true, bindingUnavailable()
		}
		return root, true, nil
	}
	return "", false, nil
}
