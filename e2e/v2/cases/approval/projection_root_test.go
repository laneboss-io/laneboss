//go:build linux && laneboss_root_canary && laneboss_gate_integration

package approval_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func init() {
	if len(os.Args) == 3 && os.Args[1] == "approval-projection-control" {
		if os.Chdir(os.Args[2]) != nil {
			os.Exit(91)
		}
		os.Args = []string{os.Args[0], "-test.run=^TestApprovalLaneProjection$", "-test.v"}
		return
	}
	if len(os.Args) == 5 && os.Args[1] == "approval-descriptor-child" {
		binding, e1 := strconv.Atoi(os.Args[2])
		socket, e2 := strconv.Atoi(os.Args[3])
		foreign, e3 := strconv.Atoi(os.Args[4])
		var a, b, c unix.Stat_t
		if e1 != nil || e2 != nil || e3 != nil || unix.Fstat(binding, &a) != nil || unix.Fstat(socket, &b) != nil || b.Mode&unix.S_IFMT != unix.S_IFSOCK || unix.Fstat(foreign, &c) == nil {
			os.Exit(81)
		}
		data := make([]byte, a.Size)
		n, err := unix.Pread(binding, data, 0)
		if err != nil || n != len(data) {
			os.Exit(82)
		}
		var value map[string]any
		if json.Unmarshal(data, &value) != nil {
			os.Exit(83)
		}
		if err := json.NewEncoder(os.Stdout).Encode(value["target"]); err != nil {
			os.Exit(84)
		}
		os.Exit(0)
	}
	if len(os.Args) != 6 || os.Args[1] != "approval-projection-namespace" {
		return
	}
	if unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "") != nil || unix.Mount("tmpfs", "/run", "tmpfs", 0, "mode=0755") != nil {
		os.Exit(85)
	}
	if os.Mkdir("/run/laneboss", 0755) != nil {
		os.Exit(86)
	}
	mode := os.Args[5]
	if mode == "regular" {
		if os.WriteFile("/run/laneboss/binding.json", []byte("{}"), 0444) != nil {
			os.Exit(87)
		}
	} else {
		link := "/proc/self/fd/6"
		if mode == "alias" {
			link = "/proc/self/fd/06"
		}
		if os.Symlink(link, "/run/laneboss/binding.json") != nil {
			os.Exit(88)
		}
	}
	if os.Symlink("/proc/self/fd/7", "/run/laneboss/service.sock") != nil {
		os.Exit(89)
	}
	command := exec.Command("python3", os.Args[2], os.Args[3], os.Args[4])
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	command.ExtraFiles = []*os.File{nil, nil, nil, os.NewFile(6, "binding"), os.NewFile(7, "socket"), os.NewFile(8, "foreign")}
	if err := command.Run(); err != nil {
		os.Exit(90)
	}
	os.Exit(0)
}

// Mutate only a disposable Python adapter copy on the Linux box. The actual
// native canary must fail on the dropped-FD assertion, then pass restored.
func TestApprovalLaneProjectionMutation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("native projection control requires the authorized root Linux box")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := os.ReadFile("harness.py")
	if err != nil {
		t.Fatal(err)
	}
	probe, err := os.ReadFile("testdata/projection_probe.py")
	if err != nil {
		t.Fatal(err)
	}
	needle := "start_new_session=True, close_fds=True, pass_fds=pass_fds)"
	if strings.Count(string(adapter), needle) != 1 {
		t.Fatal("native projection mutation target is not unique")
	}
	for _, control := range []bool{true, false} {
		root := t.TempDir()
		if err := os.Mkdir(filepath.Join(root, "testdata"), 0700); err != nil {
			t.Fatal(err)
		}
		content := adapter
		if control {
			content = []byte(strings.Replace(string(adapter), needle, "start_new_session=True, close_fds=True, pass_fds=())", 1))
		}
		if err := os.WriteFile(filepath.Join(root, "harness.py"), content, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "testdata", "projection_probe.py"), probe, 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(binary, "approval-projection-control", root)
		output, err := command.CombinedOutput()
		if control {
			if err == nil || !strings.Contains(string(output), "sealed binding/socket were not preserved") || !strings.Contains(string(output), "child did not retain exactly its lane projections") {
				t.Fatal("dropped descriptor control was not killed by the reached native assertion", err, string(output))
			}
			t.Log("native descriptor control: reached dropped-FD assertion failed")
		} else if err != nil {
			t.Fatal("restored native descriptor adapter failed", err, string(output))
		} else {
			t.Log("restored native descriptor adapter: passed")
		}
	}
}

// An actual mount namespace, sealed memfd and O_PATH socket exercise the Python
// handoff. This proves that boundary, not an authenticated service identity.
func TestApprovalLaneProjection(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("native projection canary requires the authorized root Linux box")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"retained", "unsealed", "regular", "foreign_config", "alias"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			fd, err := unix.MemfdCreate("approval-binding", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
			if err != nil {
				t.Fatal(err)
			}
			binding := os.NewFile(uintptr(fd), "binding")
			defer binding.Close()
			target := map[string]any{"life_id": "projection-life", "run": 3}
			config := "projection-case"
			if mode == "foreign_config" {
				config = "foreign-case"
			}
			value := map[string]any{"class": "lane", "config": config, "artifact_sha256": "artifact-pin", "target": target, "socket": "/run/laneboss/service.sock", "mapped_service_uid": os.Geteuid(), "mapped_service_gid": os.Getegid()}
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := binding.Write(raw); err != nil {
				t.Fatal(err)
			}
			if err := binding.Chmod(0444); err != nil {
				t.Fatal(err)
			}
			if mode != "unsealed" {
				if _, err := unix.FcntlInt(binding.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(directory, "endpoint.sock")
			socket, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(socket)
			if err := unix.Bind(socket, &unix.SockaddrUnix{Name: path}); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0666); err != nil {
				t.Fatal(err)
			}
			pinned, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				t.Fatal(err)
			}
			endpoint := os.NewFile(uintptr(pinned), "endpoint")
			defer endpoint.Close()
			foreign, err := os.CreateTemp(directory, "foreign")
			if err != nil {
				t.Fatal(err)
			}
			defer foreign.Close()
			settings := filepath.Join(directory, "settings.json")
			approvalWriteJSON(t, settings, map[string]any{"binding_file": "/run/laneboss/binding.json", "config": "projection-case", "binary_sha256": "artifact-pin", "target": target, "binary": binary})
			command := exec.Command(binary, "approval-projection-namespace", filepath.Join(root, "testdata/projection_probe.py"), root, settings, mode)
			command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
			command.ExtraFiles = []*os.File{nil, nil, nil, binding, endpoint, foreign}
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("projection canary did not reach its assertion: %v: %s", err, output)
			}
			var observed struct {
				Refused       bool
				Reason        string
				Target, Child map[string]any
			}
			if err := json.Unmarshal(output, &observed); err != nil {
				t.Fatal("missing actual projection observation", err, string(output))
			}
			if mode == "retained" {
				if observed.Refused || fmt.Sprint(observed.Target) != fmt.Sprint(observed.Child) || observed.Child["life_id"] != target["life_id"] {
					t.Fatalf("sealed binding/socket were not preserved: %+v", observed)
				}
			} else if !observed.Refused {
				t.Fatal("projection accepted " + mode)
			}
		})
	}
}
