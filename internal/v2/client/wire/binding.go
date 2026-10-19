package wire

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
)

// Fixed namespace destinations. A projected binding is a sealed inherited
// descriptor; its socket is a separate inherited O_PATH pin, not a host path.
const (
	LaneBindingPath   = "/run/laneboss/binding.json"
	LaneSocketPath    = "/run/laneboss/service.sock"
	LaneClientPath    = "/run/laneboss/client"
	WorkerBindingPath = "/runtime/laneboss-worker.json"
	WorkerSocketPath  = "/runtime/laneboss-worker.sock"
	WorkerInputPath   = "/runtime/laneboss-worker-input.json"
)

func ReadBinding(path, config, version string) (api.InstalledBinding, error) {
	var binding api.InstalledBinding
	if projected, handled, err := readProjectedBinding(path, config, version); handled {
		return projected, err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return binding, Invalid("binding path must be absolute and canonical")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > api.MaxFrameBytes || before.Mode().Perm()&0022 != 0 {
		return binding, bindingError("protected binding is missing or unsafe")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return binding, bindingError("cannot open protected binding")
	}
	after, statErr := file.Stat()
	data, readErr := io.ReadAll(io.LimitReader(file, api.MaxFrameBytes+1))
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() || !after.Mode().IsRegular() || int64(len(data)) != before.Size() {
		return binding, bindingError("binding changed during protected read")
	}
	if err := Decode(data, &binding); err != nil {
		return binding, err
	}
	if err := api.ValidateBinding(binding, config, version); err != nil {
		return binding, err
	}
	if err := validateRegularProjection(binding); err != nil {
		return binding, err
	}
	stat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || stat.Uid != 0 && (stat.Uid != binding.ServiceUID || after.Mode().Perm()&0222 != 0) {
		return binding, bindingError("binding owner or immutable mode is invalid")
	}
	if stat.Uid != 0 && binding.Class == api.EndpointHuman {
		return binding, bindingError("human binding requires administrator ownership")
	}
	if stat.Uid != 0 && !strings.HasPrefix(path, "/run/laneboss/") && !strings.HasPrefix(path, "/run/laneboss-v2/") {
		return binding, bindingError("child binding is outside the administrator-protected runtime tree")
	}
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return binding, bindingError("binding has an unsafe ancestor")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 && owner.Uid != binding.ServiceUID {
			return binding, bindingError("binding ancestor has an untrusted owner")
		}
		if directory == "/" {
			break
		}
	}
	return binding, nil
}

func ArtifactDigest() (api.Digest, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, readErr := io.Copy(h, file)
	err = errors.Join(readErr, file.Close())
	if err != nil {
		return "", err
	}
	return api.Digest(hex.EncodeToString(h.Sum(nil))), nil
}

func bindingError(message string) *api.Error {
	return &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-client", Message: message, Instead: "Repair the protected installation; preserve the active configuration binding."}
}
