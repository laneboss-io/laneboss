//go:build linux

package service

import (
	"context"
	"os"
	"reflect"
	"strconv"
	"strings"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type schedulerPin struct {
	pid        int
	boot       string
	generation string
	binding    os.FileInfo
	image      os.FileInfo
}

func schedulerProcess() (string, string, error) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", "", err
	}
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return "", "", err
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return "", "", serviceError(api.CodeIntegrity, "scheduler process identity is malformed")
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 || strings.TrimSpace(string(boot)) == "" {
		return "", "", serviceError(api.CodeIntegrity, "scheduler process lifetime is missing")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return "", "", serviceError(api.CodeIntegrity, "scheduler process generation is invalid")
	}
	return strings.TrimSpace(string(boot)), fields[19], nil
}

func pinScheduler(ctx context.Context, s *Server) (schedulerPin, error) {
	var pin schedulerPin
	if err := ctx.Err(); err != nil {
		return pin, contextError(err)
	}
	binding, err := wire.ReadBinding(s.options.BindingFile, s.options.Config, release.Version)
	if err != nil {
		return pin, err
	}
	if !reflect.DeepEqual(binding, s.deps.Binding) || binding.Class != api.EndpointHuman || os.Geteuid() == 0 ||
		uint32(os.Geteuid()) != binding.ServiceUID || uint32(os.Getegid()) != binding.ServiceGID {
		return pin, serviceError(api.CodeForbidden, "scheduler caller is not the installed service process")
	}
	digest, err := wire.ArtifactDigest()
	if err != nil {
		return pin, err
	}
	if digest != binding.ArtifactSHA256 {
		return pin, serviceError(api.CodeVersion, "scheduler executable differs from its installation")
	}
	pin.pid, pin.boot, pin.generation = os.Getpid(), "", ""
	pin.boot, pin.generation, err = schedulerProcess()
	if err != nil {
		return pin, err
	}
	pin.binding, err = os.Lstat(s.options.BindingFile)
	if err != nil {
		return pin, err
	}
	pin.image, err = os.Stat("/proc/self/exe")
	if err != nil {
		return pin, err
	}
	return pin, pin.check(ctx, s)
}

func (p schedulerPin) check(ctx context.Context, s *Server) error {
	if err := ctx.Err(); err != nil {
		return contextError(err)
	}
	binding := s.deps.Binding
	if p.pid != os.Getpid() || os.Geteuid() == 0 || uint32(os.Geteuid()) != binding.ServiceUID || uint32(os.Getegid()) != binding.ServiceGID {
		return serviceError(api.CodeForbidden, "scheduler native caller changed")
	}
	boot, generation, err := schedulerProcess()
	if err != nil {
		return err
	}
	if boot != p.boot || generation != p.generation {
		return serviceError(api.CodeForbidden, "scheduler boot or process lifetime changed")
	}
	current, err := wire.ReadBinding(s.options.BindingFile, s.options.Config, release.Version)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, binding) {
		return serviceError(api.CodeConflict, "scheduler installation generation changed")
	}
	info, err := os.Lstat(s.options.BindingFile)
	if err != nil {
		return err
	}
	image, err := os.Stat("/proc/self/exe")
	if err != nil {
		return err
	}
	if p.binding == nil || p.image == nil || !os.SameFile(info, p.binding) || !os.SameFile(image, p.image) {
		return serviceError(api.CodeForbidden, "scheduler installation or image was replaced")
	}
	return nil
}
