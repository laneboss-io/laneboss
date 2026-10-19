//go:build linux

package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	linuxunit "laneboss.io/laneboss/packaging/v2/linux"
)

const helperCapsLine = "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_SETGID CAP_SETUID CAP_SYS_PTRACE CAP_KILL CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_NET_ADMIN CAP_NET_BIND_SERVICE"

func TestProcessSetUID(t *testing.T) {
	for combination := 0; combination < 8; combination++ {
		mask := uint64(1) << unix.CAP_SETUID
		bits := [3]uint64{1 << unix.CAP_KILL, 1 << unix.CAP_SETGID, 1 << unix.CAP_SYS_ADMIN}
		for index := range bits {
			if combination&(1<<index) != 0 {
				bits[index] |= mask
			}
		}
		data := []byte(fmt.Sprintf("Name:\tignored\nCapEff:\t%016x\nCapPrm:\t%016x\nCapBnd:\t%016x\n", bits[0], bits[1], bits[2]))
		got, err := parseProcessSetUID(data)
		want := processSetUID{effective: combination&1 != 0, permitted: combination&2 != 0, bounding: combination&4 != 0, permittedSetGID: true, permittedBits: bits[1]}
		if err != nil || got != want {
			t.Fatal("acceptance: process capability facts ignored distinct kernel fields")
		}
	}
	for _, data := range []string{
		"", "CapEff: 0\nCapPrm: 0\n", "CapEff: 0\nCapPrm: 0\nCapBnd: 0\nCapEff: 0\n",
		"CapEff: invalid\nCapPrm: 0\nCapBnd: 0\n", "CapEff: 10000000000000000\nCapPrm: 0\nCapBnd: 0\n",
		"CapEff: \nCapPrm: 0\nCapBnd: 0\n", "CapEff: 0 0\nCapPrm: 0\nCapBnd: 0\n",
	} {
		state, err := parseProcessSetUID([]byte(data))
		if !errors.Is(err, unix.EINVAL) || state != (processSetUID{}) {
			t.Fatal("acceptance: incomplete process capability input became a known observation")
		}
	}
}

func TestProcessSetUIDNative(t *testing.T) {
	observed, err := readProcessSetUID()
	if err != nil {
		t.Fatal("native main-thread status is unavailable")
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: int32(os.Getpid())}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		t.Fatal("native main-thread capget control is unavailable")
	}
	mask := uint32(1) << unix.CAP_SETUID
	if observed.effective != (data[0].Effective&mask != 0) || observed.permitted != (data[0].Permitted&mask != 0) {
		t.Fatal("acceptance: main-thread proc facts disagree with kernel capget")
	}
	if observed.permittedSetGID != (data[0].Permitted&(1<<unix.CAP_SETGID) != 0) {
		t.Fatal("acceptance: main-thread GID permission disagrees with kernel capget")
	}
	if observed.permittedBits != uint64(data[0].Permitted)|uint64(data[1].Permitted)<<32 {
		t.Fatal("acceptance: complete process permitted set disagrees with kernel capget")
	}
}

func rootStartupUIDs() ([3]uint32, error) { return [3]uint32{}, nil }

func TestHelperBeforeAccounts(t *testing.T) {
	expected, err := intendedHelperCapabilities()
	if err != nil {
		t.Fatal("helper capability policy unavailable")
	}
	for _, sample := range []struct {
		name      string
		permitted uint64
		missing   string
	}{
		{"present", expected, ""},
		{"setuid", expected &^ (1 << unix.CAP_SETUID), "CAP_SETUID"},
		{"setgid", expected &^ (1 << unix.CAP_SETGID), "CAP_SETGID"},
		{"both", expected &^ (1<<unix.CAP_SETUID | 1<<unix.CAP_SETGID), "CAP_SETUID, CAP_SETGID"},
	} {
		t.Run(sample.name, func(t *testing.T) {
			// Opposite effective/bounding bits ensure neither can stand in for
			// the permitted set. Unrelated permitted bits confer no authority.
			other := uint64(1<<unix.CAP_SETUID|1<<unix.CAP_SETGID) &^ sample.permitted
			raw := []byte(fmt.Sprintf("CapEff: %x\nCapPrm: %x\nCapBnd: %x\n", other, sample.permitted|1<<unix.CAP_SYS_ADMIN, other))
			var output bytes.Buffer
			reads := 0
			err := helperBeforeAccounts(&output, func() (processSetUID, error) {
				reads++
				return parseProcessSetUID(raw)
			}, rootStartupUIDs)
			var record map[string]string
			if reads != 1 || json.Unmarshal(output.Bytes(), &record) != nil || len(record) != 2 || record["stage"] != "helper.before_accounts" {
				t.Fatal("acceptance: helper startup decision lost its single retained process observation")
			}
			if sample.missing == "" {
				if err != nil {
					t.Fatal("acceptance: helper refused present permitted credential-drop capabilities")
				}
				return
			}
			var typed *api.Error
			want := "helper.before_accounts: process permitted set lacks " + sample.missing + "; inspect the installed laneboss-helper systemd unit (User/NoNewPrivileges policy)"
			if !errors.As(err, &typed) || typed.Owner != "lb-v2-admin" || typed.Code != api.CodePrerequisite || typed.Message != want {
				t.Fatal("acceptance: helper startup did not refuse the missing permitted capability with its typed unit diagnostic")
			}
		})
	}
	t.Run("unavailable", func(t *testing.T) {
		var output bytes.Buffer
		private, err := randomID("private-")
		if err != nil {
			t.Fatal(err)
		}
		err = helperBeforeAccounts(&output, func() (processSetUID, error) {
			return parseProcessSetUID([]byte("CapEff: " + string(private) + "\nCapPrm: 0\nCapBnd: 0\n"))
		}, rootStartupUIDs)
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodePrerequisite || !strings.Contains(typed.Message, "cannot read process permitted CAP_SETUID/CAP_SETGID") || !strings.Contains(typed.Message, "installed laneboss-helper systemd unit") || strings.Contains(output.String()+typed.Message, string(private)) {
			t.Fatal("acceptance: helper startup admitted or disclosed unavailable capability input")
		}
	})
}

func TestHelperExactStartup(t *testing.T) {
	expected, err := intendedHelperCapabilities()
	pinned, pinErr := helperCapabilitySet("[Service]\n" + helperCapsLine + "\n")
	policyLine := ""
	for _, line := range strings.Split(linuxunit.HelperTemplate(), "\n") {
		if strings.HasPrefix(line, "CapabilityBoundingSet=") {
			policyLine = line
		}
	}
	if err != nil || pinErr != nil || expected&(1<<unix.CAP_CHOWN) == 0 || expected != pinned || policyLine != helperCapsLine {
		t.Fatal("exact startup fixture requires the actual helper policy")
	}
	nonzero := uint32(os.Getpid() + 1000)
	for _, sample := range []struct {
		name   string
		bits   uint64
		ids    [3]uint32
		code   api.ErrorCode
		uidErr error
	}{
		{"exact", expected, [3]uint32{}, "", nil},
		{"missing", expected &^ (1 << unix.CAP_CHOWN), [3]uint32{}, api.CodePrerequisite, nil},
		{"extra", expected | (1 << unix.CAP_NET_RAW), [3]uint32{}, api.CodePrerequisite, nil},
		{"real", expected, [3]uint32{nonzero, 0, 0}, api.CodeForbidden, nil},
		{"effective", expected, [3]uint32{0, nonzero, 0}, api.CodeForbidden, nil},
		{"saved", expected, [3]uint32{0, 0, nonzero}, api.CodeForbidden, nil},
		{"uiderror", expected, [3]uint32{}, api.CodePrerequisite, unix.EPERM},
	} {
		t.Run(sample.name, func(t *testing.T) {
			var output bytes.Buffer
			reads, uidReads := 0, 0
			err := helperBeforeAccounts(&output, func() (processSetUID, error) {
				reads++
				return parseProcessSetUID([]byte(fmt.Sprintf("CapEff: 0\nCapPrm: %x\nCapBnd: 0\n", sample.bits)))
			}, func() ([3]uint32, error) {
				uidReads++
				return sample.ids, sample.uidErr
			})
			if reads != 1 || uidReads != 1 {
				t.Fatal("acceptance: exact startup did not read actual capability and UID inputs once")
			}
			if sample.code == "" {
				if err != nil {
					t.Fatal("acceptance: exact helper policy and root UIDs were refused")
				}
			} else {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Owner != "lb-v2-admin" || typed.Code != sample.code {
					t.Fatal("acceptance: helper startup admitted a nonexact permitted set or nonroot UID")
				}
			}
		})
	}
}

func TestHelperUIDsNative(t *testing.T) {
	observed, err := readHelperUIDs()
	if err != nil {
		t.Fatal("native UID observation is unavailable")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal("independent UID status is unavailable")
	}
	found := false
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		parts := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if found || len(parts) != 4 {
			t.Fatal("independent UID status is ambiguous")
		}
		found = true
		for index := range observed {
			value, err := strconv.ParseUint(parts[index], 10, 32)
			if err != nil || observed[index] != uint32(value) {
				t.Fatal("acceptance: native real/effective/saved UIDs disagree with procfs")
			}
		}
	}
	if !found {
		t.Fatal("independent UID status is absent")
	}
}

func TestHelperPolicyTemplate(t *testing.T) {
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := helperUnitFixture(directory)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != linuxunit.HelperTemplate() {
		t.Fatal("acceptance: helper startup policy is not the actual installer template")
	}
	mask, err := helperCapabilitySet(string(raw))
	if err != nil || mask&(1<<unix.CAP_SETUID|1<<unix.CAP_SETGID) != 1<<unix.CAP_SETUID|1<<unix.CAP_SETGID {
		t.Fatal("acceptance: actual template did not supply credential capabilities")
	}
	for _, invalid := range []string{
		"[Service]\n", "[Service]\nCapabilityBoundingSet=\n",
		"[Service]\nCapabilityBoundingSet=CAP_CHOWN\nCapabilityBoundingSet=CAP_KILL\n",
		"[Service]\nCapabilityBoundingSet=CAP_CHOWN CAP_CHOWN\n",
		"[Service]\nCapabilityBoundingSet=~CAP_CHOWN\n", "[Service]\nCapabilityBoundingSet=unknown\n",
	} {
		if _, err := helperCapabilitySet(invalid); !errors.Is(err, unix.EINVAL) {
			t.Fatal("acceptance: ambiguous helper capability policy was admitted")
		}
	}
}
