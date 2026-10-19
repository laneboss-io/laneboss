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

func projectionMemfd(t *testing.T, data []byte, mode uint32, seals int) *os.File {
	t.Helper()
	fd, err := unix.MemfdCreate("projection-fixture", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "projection-fixture")
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	if n, err := file.Write(data); err != nil || n != len(data) {
		t.Fatal("could not retain projection fixture bytes", err)
	}
	if err := file.Chmod(os.FileMode(mode)); err != nil {
		t.Fatal(err)
	}
	if seals != 0 {
		if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
			t.Fatal(err)
		}
	}
	return file
}

const projectionSeals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL

func laneBindingFixture() api.InstalledBinding {
	return api.InstalledBinding{Schema: "laneboss.binding.v2", Config: "projection-fixture", Protocol: api.Protocol, APISchema: api.SchemaVersion, ContractRevision: api.ContractRevision,
		Class: api.EndpointLane, InstallationGeneration: 3, EndpointGeneration: 7, ServiceVersion: "projection-release", ServiceUID: 41001, ServiceGID: 41002,
		MappedServiceUID: uint32(os.Geteuid()), MappedServiceGID: uint32(os.Getegid()), Socket: LaneSocketPath,
		ArtifactSHA256: api.Digest(strings.Repeat("a", 64)), Backend: "linux-bwrap-landlock", LaunchID: "projection-launch", Target: &api.LifeRef{LifeID: "projection-life", Run: 2}}
}

func TestLaneBindingSealedProof(t *testing.T) {
	base := laneBindingFixture()
	for _, fault := range []string{"valid", "unsealed", "seal-write", "seal-grow", "seal-shrink", "seal-seal", "mode", "class", "socket", "config", "version", "target", "unknown"} {
		t.Run(fault, func(t *testing.T) {
			binding := base
			mode, seals := uint32(0444), projectionSeals
			switch fault {
			case "unsealed":
				seals = 0
			case "seal-write":
				seals &^= unix.F_SEAL_WRITE
			case "seal-grow":
				seals &^= unix.F_SEAL_GROW
			case "seal-shrink":
				seals &^= unix.F_SEAL_SHRINK
			case "seal-seal":
				seals &^= unix.F_SEAL_SEAL
			case "mode":
				mode = 0644
			case "class":
				binding.Class = api.EndpointHuman
				binding.LaunchID, binding.Target = "", nil
			case "socket":
				binding.Socket = WorkerSocketPath
			case "config":
				binding.Config = "other-projection"
			case "version":
				binding.ServiceVersion = "other-release"
			case "target":
				binding.Target = nil
			}
			raw, err := json.Marshal(binding)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "unknown" {
				raw = append(raw[:len(raw)-1], []byte(",\"unrecognized\":true}")...)
			}
			raw = append(raw, '\n')
			file := projectionMemfd(t, raw, mode, seals)
			for attempt := 0; attempt < 2; attempt++ {
				actual, err := readBindingFD(int(file.Fd()), base.Config, base.ServiceVersion, api.EndpointLane, LaneSocketPath)
				if fault == "valid" {
					if err != nil || !reflect.DeepEqual(actual, base) {
						t.Fatal("sealed lane binding lost exact run or repeatable descriptor reads", err)
					}
				} else if err == nil {
					t.Fatal("lane binding accepted missing sealed proof or a changed endpoint")
				}
			}
		})
	}
}

func TestWorkerInputSealedBytes(t *testing.T) {
	data := []byte("{\n  \"input\": \"" + string(laneBindingFixture().LaunchID) + "\"\n}\n")
	digest := sha256.Sum256(data)
	base := api.BlobRef{ID: "worker-input", SHA256: api.Digest(hex.EncodeToString(digest[:])), Bytes: int64(len(data)), Class: "materialize_input"}
	for _, fault := range []string{"valid", "archive", "unsealed", "mode", "hash", "size", "class", "bytes"} {
		t.Run(fault, func(t *testing.T) {
			ref, raw, mode, seals := base, append([]byte(nil), data...), uint32(0444), projectionSeals
			switch fault {
			case "archive":
				ref.Class = "archive_input"
			case "unsealed":
				seals = 0
			case "mode":
				mode = 0600
			case "hash":
				ref.SHA256 = api.Digest(strings.Repeat("0", 64))
			case "size":
				ref.Bytes++
			case "class":
				ref.Class = "manifest"
			case "bytes":
				raw[len(raw)-1] = ' '
			}
			file := projectionMemfd(t, raw, mode, seals)
			for attempt := 0; attempt < 2; attempt++ {
				actual, err := readWorkerInputFD(int(file.Fd()), ref)
				if fault == "valid" || fault == "archive" {
					if err != nil || !bytes.Equal(actual, data) {
						t.Fatal("inherited worker input changed exact bytes or descriptor offset", err)
					}
				} else if err == nil {
					t.Fatal("worker accepted altered or unsealed input")
				}
			}
		})
	}
}
