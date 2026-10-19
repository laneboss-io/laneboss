//go:build linux

package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCollectRuntimePublication(t *testing.T) {
	// Exercise the producer that writes the referencing object, including its
	// validation, sealed initial transaction and retained-byte readback. Only
	// the native channel and file-backed StateStore are component fixtures.
	b := initialFixture(t)
	var runtime api.RuntimeManifest
	if err := api.DecodeObject(b.objects[b.manifest.Runtime.ID], &runtime); err != nil {
		t.Fatal(err)
	}
	directory := privateTestDir(t)
	if err := os.Mkdir(filepath.Join(directory, "runtime"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, object := range runtime.Objects {
		if err := os.WriteFile(filepath.Join(directory, string(object.RootID), object.RelativePath), b.objects[object.Content.ID], os.FileMode(object.Mode)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"claude", "claudock"} {
		path := filepath.Join(directory, "runtime", name)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0555)
		if err != nil {
			t.Fatal(err)
		}
		size := int64(29)
		if name == "claude" {
			size = api.MaxObjectBytes + 1 // Real file, beyond the SQL blob allowance.
		}
		if err := file.Truncate(size); err != nil {
			file.Close()
			t.Fatal(err)
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		ref := api.BlobRef{ID: api.ID(name), Class: "artifact", Bytes: size, SHA256: api.Digest(hex.EncodeToString(hash.Sum(nil)))}
		runtime.Objects = append(runtime.Objects, api.RuntimeObject{ID: api.ID(name), Role: name, RootID: "runtime", RelativePath: name, Mode: 0555, Content: ref})
	}
	replaceInitialDoc(t, &b, &b.manifest.Runtime, runtime)
	var launch api.LaunchEnrollment
	if err := api.DecodeObject(b.objects[b.manifest.Launch.ID], &launch); err != nil {
		t.Fatal(err)
	}
	for i := range launch.Runtimes {
		launch.Runtimes[i].Manifest = b.manifest.Runtime
	}
	replaceInitialDoc(t, &b, &b.manifest.Launch, launch)
	ctx, channel := initialTestContext(t)
	state := &initialTestStore{path: filepath.Join(directory, "state.json")}
	if _, err := commitInitial(ctx, b, state, enrollmentClock{now: time.Now().UTC()}, channel); err != nil {
		t.Fatal("real initial-publication producer refused file-backed vendor pins", err)
	}
	disk, err := state.load()
	if err != nil {
		t.Fatal(err)
	}
	var published api.RuntimeManifest
	if err := api.DecodeObject(disk.Objects[b.manifest.Runtime.ID], &published); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), disk.Objects[b.manifest.Runtime.ID], 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "roots.json"), initialEncode(t, []enrolledRoot{{ID: "runtime", Path: filepath.Join(directory, "runtime")}}), 0444); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	binding := testBinding()
	binding.Artifact.SHA256, binding.Release.Version = published.Artifact.SHA256, published.Artifact.Version
	service := &Service{binding: binding, deps: Dependencies{Config: b.manifest.Config, RuntimeManifest: b.manifest.Runtime},
		files: &enrollmentFiles{root: root, base: directory, owner: uint32(os.Geteuid())}}
	var vendor api.BlobRef
	for _, object := range published.Objects {
		if !vendorRuntime(object) {
			continue
		}
		if _, exists := disk.Objects[object.Content.ID]; exists {
			t.Fatal("initial publication copied vendor bytes into its object store")
		}
		first, err := service.ReadCleanupRuntime(context.Background(), object.Content)
		if err != nil {
			t.Fatal("published runtime has an unresolved installed artifact", object.Content.ID, err)
		}
		second, err := service.ReadCleanupRuntime(context.Background(), object.Content)
		if err != nil || second != first || first.Ref != object.Content || first.Role != "runtime" || first.OwnerLifeID != "" || first.Identity == "" || first.RootIdentity == "" {
			t.Fatal("installed artifact lacks stable independently measured identity", err)
		}
		vendor = object.Content
	}
	if vendor.ID == "" {
		t.Fatal("producer test lost both vendor references")
	}
	foreign := vendor
	foreign.ID = "absent-vendor"
	if _, err := service.ReadCleanupRuntime(context.Background(), foreign); err == nil {
		t.Fatal("unselected missing artifact was accepted")
	}
	foreign = vendor
	foreign.SHA256 = testDigest("different bytes")
	if _, err := service.ReadCleanupRuntime(context.Background(), foreign); err == nil {
		t.Fatal("same-name artifact with a different digest was accepted")
	}
	path := filepath.Join(directory, "runtime", string(vendor.ID))
	if err := os.Rename(path, path+".held"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReadCleanupRuntime(context.Background(), vendor); err == nil {
		t.Fatal("absent installed file was accepted from its manifest pin")
	}
	if err := os.Rename(path+".held", path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReadCleanupRuntime(context.Background(), vendor); err == nil {
		t.Fatal("writable installed executable was accepted")
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	written, writeErr := file.WriteAt([]byte{1}, 0)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil || written != 1 {
		t.Fatal("cannot corrupt the file without changing its size", writeErr, closeErr)
	}
	if err := os.Chmod(path, 0555); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReadCleanupRuntime(context.Background(), vendor); err == nil {
		t.Fatal("changed installed bytes were accepted")
	}
}
