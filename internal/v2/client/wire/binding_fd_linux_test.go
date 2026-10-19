//go:build linux

package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestWorkerInputKinds(t *testing.T) {
	for _, class := range []string{"materialize_input", "archive_input", "usage_input", "channel_input"} {
		t.Run(class, func(t *testing.T) {
			raw := []byte("exact sealed " + class + "\n")
			fd, err := unix.MemfdCreate("input-kind", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
			if err != nil {
				t.Fatal(err)
			}
			file := os.NewFile(uintptr(fd), "input-kind")
			defer file.Close()
			if n, err := file.Write(raw); err != nil || n != len(raw) {
				t.Fatal("input kind fixture did not retain its bytes", err)
			}
			if err := file.Chmod(0444); err != nil {
				t.Fatal(err)
			}
			const seals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
			if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(raw)
			ref := api.BlobRef{ID: "worker-input-kind", Class: class, Bytes: int64(len(raw)), SHA256: api.Digest(hex.EncodeToString(sum[:]))}
			actual, err := readWorkerInputFD(fd, ref)
			if err != nil || !bytes.Equal(actual, raw) {
				t.Fatal("native input reader lost a supported worker kind", err)
			}
		})
	}
}

func TestWorkerBindingFD(t *testing.T) {
	version := "component-binding-version"
	base := api.InstalledBinding{Schema: "laneboss.binding.v2", Config: "binding-fd", Protocol: api.Protocol, APISchema: api.SchemaVersion, ContractRevision: api.ContractRevision,
		Class: api.EndpointWorker, InstallationGeneration: 1, EndpointGeneration: 1, ServiceVersion: version, ServiceUID: 41001, ServiceGID: 41001,
		Socket: "/runtime/laneboss-worker.sock", ArtifactSHA256: api.Digest(strings.Repeat("a", 64)), Backend: "linux-bwrap-landlock", LaunchID: "binding-launch", WorkerLeaseID: "binding-worker", Target: &api.LifeRef{LifeID: "binding-life", Run: 1}}
	for _, fault := range []string{"valid", "unsealed", "writable", "class", "socket", "config", "version"} {
		t.Run(fault, func(t *testing.T) {
			binding := base
			config, requestedVersion := base.Config, version
			switch fault {
			case "class":
				binding.Class = api.EndpointLane
			case "socket":
				binding.Socket = "/runtime/foreign.sock"
			case "config":
				config = "other-binding"
			case "version":
				requestedVersion = "other-version"
			}
			data, err := json.Marshal(binding)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, '\n')
			fd, err := unix.MemfdCreate("worker-binding-fixture", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
			if err != nil {
				t.Fatal(err)
			}
			file := os.NewFile(uintptr(fd), "binding-fixture")
			defer file.Close()
			if n, err := file.Write(data); err != nil || n != len(data) {
				t.Fatal("worker binding fixture could not retain its input bytes")
			}
			if fault != "writable" {
				if err := file.Chmod(0444); err != nil {
					t.Fatal(err)
				}
			}
			if fault != "unsealed" {
				const seals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
				if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
					t.Fatal(err)
				}
			}
			for attempt := 0; attempt < 2; attempt++ {
				actual, err := readWorkerBindingFD(fd, config, requestedVersion)
				if fault == "valid" {
					if err != nil || !reflect.DeepEqual(actual, base) {
						t.Fatal("acceptance: sealed worker binding lost exact bytes or repeatable descriptor reads")
					}
				} else if err == nil {
					t.Fatal("acceptance: unsafe inherited worker binding was accepted")
				}
			}
		})
	}
}
