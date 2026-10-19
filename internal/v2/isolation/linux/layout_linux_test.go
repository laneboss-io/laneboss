//go:build linux

package linux

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func hasSequence(args []string, sequence ...string) bool {
	for index := 0; index+len(sequence) <= len(args); index++ {
		if reflect.DeepEqual(args[index:index+len(sequence)], sequence) {
			return true
		}
	}
	return false
}

func TestDescriptorMountArguments(t *testing.T) {
	plan := launchPlan{helper: &pinnedMount{source: "/installed/helper", target: helperPath, readOnly: true},
		runtime: []*pinnedMount{{source: "/usr", target: "/usr", readOnly: true}},
		data: []*pinnedMount{{source: "/fixture/work", target: "/work/main"},
			{source: "/fixture/input", target: "/data/input", readOnly: true}},
		links: [][2]string{{"usr/bin", "/bin"}}}
	args, files := buildArgs(plan)
	if len(files) != 4 {
		t.Fatal("missing pinned mount descriptors")
	}
	for _, flag := range []string{"--die-with-parent", "--new-session", "--unshare-user", "--unshare-pid",
		"--unshare-ipc", "--unshare-uts", "--unshare-net", "--clearenv"} {
		if !hasSequence(args, flag) {
			t.Fatalf("missing namespace flag %s", flag)
		}
	}
	for _, sequence := range [][]string{
		{"--cap-drop", "ALL"}, {"--proc", "/proc"}, {"--dev", "/dev"},
		{"--ro-bind", "/proc/self/fd/5", "/usr"}, {"--bind", "/proc/self/fd/6", "/work/main"},
		{"--ro-bind", "/proc/self/fd/7", "/data/input"}, {"--ro-bind", "/proc/self/fd/8", helperPath},
		{"--seccomp", "4"}, {"--tmpfs", "/tmp"}, {"--tmpfs", "/home/lane"},
		{"--remount-ro", "/proc"}, {"--remount-ro", "/", "--", helperPath, helperFlag, "3"},
	} {
		if !hasSequence(args, sequence...) {
			t.Fatal("missing mount or bootstrap boundary")
		}
	}
	for index, arg := range args {
		if arg == "--disable-userns" || arg == "--assert-userns-disabled" {
			t.Fatal("acceptance: isolation builder restored a sysctl-based user namespace option")
		}
		if (arg == "--bind" || arg == "--ro-bind") && (index+1 >= len(args) || !strings.HasPrefix(args[index+1], "/proc/self/fd/")) {
			t.Fatal("mount used an unpinned source")
		}
		if arg == "--bind-fd" || arg == "--ro-bind-fd" || arg == "--ro-bind-data" ||
			arg == "/fixture/work" || arg == "/fixture/input" || arg == "/installed/helper" {
			t.Fatal("mount used an unpinned source or named payload")
		}
	}
}

func TestNoHostNetworkFallback(t *testing.T) {
	_, _, err := prepareSandbox(sandboxSpec{Network: true})
	var typed *PrerequisiteError
	if !errors.As(err, &typed) || typed.Check != "controlled_egress" || typed.Err == nil {
		t.Fatal("network requested without a private egress lease")
	}
	plan := launchPlan{helper: &pinnedMount{target: helperPath}}
	args, _ := buildArgs(plan)
	if !hasSequence(args, "--unshare-net") {
		t.Fatal("network namespace was shared")
	}
}

func TestExportsCannotOverlapRuntime(t *testing.T) {
	base := launchPlan{helper: &pinnedMount{source: "/opt/lb/helper", target: helperPath},
		runtime: []*pinnedMount{{source: "/usr", target: "/usr", readOnly: true}}}
	base.data = []*pinnedMount{{source: "/fixture/work", target: "/work/main"}}
	if err := checkExportOverlaps(base, nil); err != nil {
		t.Fatal("disjoint control failed:", err)
	}
	for _, source := range []string{"/opt/lb", "/opt/lb/helper", "/usr/local/work", "/usr", "/"} {
		plan := base
		plan.data = []*pinnedMount{{source: source, target: "/work/main"}}
		err := checkExportOverlaps(plan, nil)
		if err == nil || !strings.Contains(err.Error(), "/work/main") {
			t.Fatal("runtime/helper overlap or export name lost")
		}
	}
	if err := checkExportOverlaps(base, []string{"/usr/private-state"}); err == nil {
		t.Fatal("runtime exposed protected state")
	}
}

func TestPinSurvivesAncestorSwap(t *testing.T) {
	root := t.TempDir()
	source, moved, outside := filepath.Join(root, "source"), filepath.Join(root, "moved"), filepath.Join(root, "outside")
	for _, path := range []string{source, outside} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for path, data := range map[string]string{filepath.Join(source, "record"): "selected", filepath.Join(outside, "record"): "ungranted"} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	item, err := pinPath(source, "/work/main", false)
	if err != nil {
		t.Fatal(err)
	}
	defer item.file.Close()
	if err := os.Rename(source, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, source); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Openat2(int(item.file.Fd()), "record", &unix.OpenHow{
		Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "pinned-record")
	got, readErr := io.ReadAll(file)
	if err := errors.Join(readErr, file.Close()); err != nil {
		t.Fatal(err)
	}
	control, err := os.ReadFile(filepath.Join(source, "record"))
	if err != nil || string(control) != "ungranted" || string(got) != "selected" {
		t.Fatal("path-swap control or pinned read failed")
	}
	after, err := identify(int(item.file.Fd()))
	if err != nil || after.Device != item.identity.Device || after.Inode != item.identity.Inode {
		t.Fatal("pinned inode identity changed")
	}
}

func TestProtectedDanglingAndXDG(t *testing.T) {
	root := t.TempDir()
	link, target := filepath.Join(root, "link"), filepath.Join(root, "future")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolvePath(filepath.Join(link, "state"))
	if err != nil || resolved != filepath.Join(target, "state") {
		t.Fatal("dangling protected root lost its target")
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "xdg-config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "xdg-state"))
	for _, name := range []string{"LANEBOSS_HOME", "LANEBOSS_STATE_HOME"} {
		t.Setenv(name, "")
	}
	roots, err := protectedRoots([]string{filepath.Join(link, "state")})
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{filepath.Join(target, "state"), "/etc/laneboss",
		filepath.Join(root, "xdg-config/laneboss"), filepath.Join(root, "xdg-state/laneboss")} {
		found := false
		for _, candidate := range roots {
			found = found || candidate == wanted
		}
		if !found {
			t.Fatal("protected root missing")
		}
	}
	if _, err := protectedRoots(nil); err == nil {
		t.Fatal("accepted an unnamed state root set")
	}
}

func TestPinnedExportLinkAndTypeChecks(t *testing.T) {
	root := t.TempDir()
	work, state := filepath.Join(root, "work"), filepath.Join(root, "state")
	for _, dir := range []string{work, state} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(state, "record")
	if err := os.WriteFile(outside, []byte("ungranted"), 0644); err != nil {
		t.Fatal(err)
	}
	item, err := pinPath(work, "/work/main", false)
	if err != nil {
		t.Fatal(err)
	}
	defer item.file.Close()
	check := func() error { return validatePinnedExport(item, true, uint32(os.Geteuid()), []string{state}) }
	if err := check(); err != nil {
		t.Fatal("empty private work control:", err)
	}
	if err := os.Link(outside, filepath.Join(work, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil {
		t.Fatal("external hardlink was exported")
	}
	if err := os.Remove(filepath.Join(work, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(work, "link")); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil {
		t.Fatal("escaping symlink was exported")
	}
	if err := os.Remove(filepath.Join(work, "link")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(work, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil {
		t.Fatal("FIFO was exported")
	}
}

func TestSelectedPayloadAndSeals(t *testing.T) {
	t.Setenv("LB_NOT_SELECTED", "ambient-canary")
	env, err := selectedEnvironment([]string{"LB_SELECTED=line\nwith symbols;$`"})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range env {
		if strings.HasPrefix(value, "LB_NOT_SELECTED=") {
			t.Fatal("ambient environment was inherited")
		}
	}
	for _, selected := range [][]string{{"HOME=other"}, {"LD_PRELOAD=other"},
		{"LANEBOSS_CONFIG=other"}, {"A=one", "A=two"}, {"1A=bad"}, {"A=\x00bad"}} {
		if _, err := selectedEnvironment(selected); err == nil {
			t.Fatal("reserved or malformed injection accepted")
		}
	}
	payload := launchPayload{Mode: "run", Argv: []string{"/usr/bin/tool"}, Environment: env}
	file, err := sealedPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteAt([]byte("altered"), 0); !errors.Is(err, unix.EPERM) {
		t.Fatal("sealed bytes could be changed")
	}
	duplicate, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 10)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readSealedPayload(duplicate)
	if err != nil || !reflect.DeepEqual(got, payload) {
		t.Fatal("sealed payload bytes changed")
	}
	plain, err := os.CreateTemp(t.TempDir(), "cleartext")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if _, err := readSealedPayload(int(plain.Fd())); err == nil {
		t.Fatal("plain named payload accepted")
	}
	for _, data := range []string{`{"mode":"run","unknown":"secret"}`, `{"mode":"run"} {}`} {
		_, err := decodePayload(strings.NewReader(data))
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("bad payload accepted or its value leaked")
		}
	}
}

func TestInternalHardlinkControl(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	if err := os.WriteFile(first, []byte("private-data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(first, filepath.Join(root, "second")); err != nil {
		t.Fatal(err)
	}
	item, err := pinPath(root, "/work/main", false)
	if err != nil {
		t.Fatal(err)
	}
	defer item.file.Close()
	if err := validatePinnedExport(item, false, uint32(os.Geteuid()), nil); err != nil {
		t.Fatal("safe internal hardlink was refused:", err)
	}
	outside := filepath.Join(t.TempDir(), "external")
	if err := os.Link(first, outside); err != nil {
		t.Fatal(err)
	}
	if err := validatePinnedExport(item, false, uint32(os.Geteuid()), nil); err == nil {
		t.Fatal("an external alias escaped link counting")
	}
}

func TestStreamAndTailBoundaries(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "state-log")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, name := range []string{"stdin", "stdout", "stderr"} {
		if err := checkStream(name, file); err == nil {
			t.Fatal("file-backed state stream accepted")
		}
	}
	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := checkStream("stdin", directory); err == nil {
		t.Fatal("directory stream accepted")
	}
	var absent *os.File
	if err := checkStream("stdin", absent); err == nil {
		t.Fatal("nil file stream accepted")
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	if err := checkStream("stdout", write); err != nil {
		t.Fatal("intentional pipe refused:", err)
	}
	tail := &boundedTail{max: 4}
	for _, data := range [][]byte{[]byte("ab"), []byte("cde"), []byte("fghijkl")} {
		if n, err := tail.Write(data); err != nil || n != len(data) {
			t.Fatal("diagnostic tail write failed")
		}
	}
	if !bytes.Equal(tail.bytes(), []byte("ijkl")) {
		t.Fatal("stderr tail was not bounded correctly")
	}
}
