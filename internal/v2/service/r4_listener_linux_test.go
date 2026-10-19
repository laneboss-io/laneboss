//go:build linux

package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestArchiveEndpointLifetime(t *testing.T) {
	host := fixtureServer(t)
	directory := privateHostDirectory(t)
	host.deps.Binding.Socket = filepath.Join(directory, "service.sock")
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Cleanup(func() { cancel(); host.workers.Wait() })
	first, second := fixtureID(t), fixtureID(t)
	sealed := api.InstalledBinding{Config: host.options.Config, Class: api.EndpointWorker, ServiceUID: uint32(os.Geteuid()), ServiceGID: uint32(os.Getegid())}
	for _, lease := range []api.ID{first, second} {
		if err := host.startWorkerEndpoint(parent, lease, sealed); err != nil {
			t.Fatal(err)
		}
	}
	ctx, finish := context.WithTimeout(parent, 5*time.Second)
	defer finish()
	if err := host.stopWorkerEndpoint(ctx, fixtureID(t)); err != nil {
		t.Fatal(err)
	}
	path := func(id api.ID) string { return filepath.Join(directory, "workers", string(id)+".sock") }
	for _, lease := range []api.ID{first, second} {
		if _, err := os.Lstat(path(lease)); err != nil {
			t.Fatal("foreign lease selector stopped an unrelated endpoint", err)
		}
	}
	if err := host.stopWorkerEndpoint(ctx, first); err != nil {
		t.Fatal("archive lease endpoint did not stop at retirement", err)
	}
	if _, err := os.Lstat(path(first)); !os.IsNotExist(err) {
		t.Fatal("retired archive socket was retained", err)
	}
	if _, err := os.Lstat(path(second)); err != nil {
		t.Fatal("retiring one archive stopped another lease", err)
	}
	if err := host.stopWorkerEndpoint(ctx, second); err != nil {
		t.Fatal(err)
	}
}
