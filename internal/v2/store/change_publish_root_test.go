//go:build linux && laneboss_root_canary && laneboss_gate_integration

package store

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	if len(os.Args) != 5 || os.Args[1] != "org-publication-fs-canary" {
		return
	}
	mode, root, marker := os.Args[2], os.Args[3], []byte(os.Args[4])
	if mode == "writer" {
		file, err := os.Open(root)
		if err != nil {
			os.Exit(81)
		}
		defer file.Close()
		if orgWrite(file, "scripts/check.sh", marker, 0755) != nil {
			os.Exit(82)
		}
		ref := api.BlobRef{ID: "native-content", SHA256: api.Digest(hash(marker)), Class: "artifact", Bytes: int64(len(marker))}
		if orgInventory(file, []api.ResourceFile{{Source: api.SourceRef{Path: "scripts/check.sh"}, Content: ref, Mode: 0755}}) != nil {
			os.Exit(83)
		}
	} else if mode == "lane" {
		if err := os.WriteFile(filepath.Join(root, "workspace", "control"), marker, 0600); err != nil {
			os.Exit(84)
		}
		err := os.WriteFile(filepath.Join(root, "canonical", "scripts", "check.sh"), marker, 0755)
		if !errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.EROFS) {
			os.Exit(85)
		}
	} else if mode == "alias" {
		file, err := os.Open(root)
		if err != nil {
			os.Exit(87)
		}
		defer file.Close()
		var facts unix.Stat_t
		if unix.Fstatat(int(file.Fd()), "scripts/check.sh", &facts, unix.AT_SYMLINK_NOFOLLOW) != nil || facts.Nlink != 2 || facts.Uid != uint32(os.Geteuid()) {
			os.Exit(88)
		}
		// A raw open reads these aliased bytes; the product's pinned readback
		// must refuse the very same inode for its actual extra link.
		raw, err := os.ReadFile(filepath.Join(root, "scripts/check.sh"))
		if err != nil || string(raw) != string(marker) {
			os.Exit(89)
		}
		if _, err := orgRead(file, "scripts/check.sh", int64(len(marker)), 0755); err == nil {
			os.Exit(90)
		}
	} else {
		os.Exit(86)
	}
	os.Exit(0)
}

// This canary measures the publisher filesystem primitives under distinct real
// unprivileged UIDs. It is separate from store/claim and physical-owner proof.
func TestOrgPublicationNativeIsolation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("native org publication canary requires the authorized root Linux box")
	}
	root, err := os.MkdirTemp("", "lb-v2-org-publication-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	const serviceUID, laneUID = 240011, 240012
	for name, uid := range map[string]int{"canonical": serviceUID, "workspace": laneUID} {
		path := filepath.Join(root, name)
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, uid, uid); err != nil {
			t.Fatal(err)
		}
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(root, "native-canary")
	if err := os.WriteFile(helper, raw, 0555); err != nil {
		t.Fatal(err)
	}
	approved, attempted := string(testID(t)), string(testID(t))
	for _, phase := range []struct {
		mode, path, marker string
		uid                uint32
	}{{"writer", filepath.Join(root, "canonical"), approved, serviceUID}, {"lane", root, attempted, laneUID}} {
		command := exec.Command(helper, "org-publication-fs-canary", phase.mode, phase.path, phase.marker)
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: phase.uid, Gid: phase.uid}}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatal("native publication canary failed", err, string(output))
		}
	}
	data, err := os.ReadFile(filepath.Join(root, "canonical", "scripts", "check.sh"))
	if err != nil || string(data) != approved {
		t.Fatal("native lane changed canonical approved bytes", err)
	}
	data, err = os.ReadFile(filepath.Join(root, "workspace", "control"))
	if err != nil || string(data) != attempted {
		t.Fatal("positive lane write control did not actually change its workspace", err)
	}
	// Reached link control: the same reader must reject an actual replacement
	// with a hard link rather than accepting matching byte/hash assertions.
	if err := os.Link(filepath.Join(root, "canonical", "scripts", "check.sh"), filepath.Join(root, "canonical", "scripts", "extra-link")); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(helper, "org-publication-fs-canary", "alias", filepath.Join(root, "canonical"), approved)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: serviceUID, Gid: serviceUID}}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatal("service-owned hardlink readback control failed", err, string(output))
	}
	var info unix.Stat_t
	if err := unix.Stat(filepath.Join(root, "canonical", "scripts", "check.sh"), &info); err != nil || info.Nlink != 2 {
		t.Fatal("native hardlink control was not reached", err)
	}
}
