package linux

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func requireCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func statFixture(pid int, name, state, ticks string) []byte {
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[19] = state, ticks
	return []byte(fmt.Sprintf("%d (%s) %s", pid, name, strings.Join(fields, " ")))
}

func TestProcessGeneration(t *testing.T) {
	for _, ticks := range []string{"1", "1234567"} {
		data := statFixture(123, "with ) spaces (", "S", ticks)
		got, err := processTicks(123, data)
		if err != nil || got != ticks {
			t.Fatalf("generation parsing failed: %v", err)
		}
	}
	for _, data := range [][]byte{statFixture(124, "peer", "S", "1"),
		statFixture(123, "peer", "Z", "1"), statFixture(123, "peer", "X", "1"),
		statFixture(123, "peer", "S", "0"), statFixture(123, "peer", "S", "bad"),
		[]byte("123 (truncated) S")} {
		_, err := processTicks(123, data)
		requireCode(t, err, api.CodeUnauthenticated)
	}
}

func TestCredentialDrift(t *testing.T) {
	base := "Uid:\t1234\t1234\t1234\t1234\nGid:\t5678\t5678\t5678\t5678\n"
	if err := checkIDs([]byte(base), 1234, 5678); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"Uid", "Gid"} {
		for index := 0; index < 4; index++ {
			uid := []string{"1234", "1234", "1234", "1234"}
			gid := []string{"5678", "5678", "5678", "5678"}
			if kind == "Uid" {
				uid[index] = "1235"
			} else {
				gid[index] = "5679"
			}
			data := "Uid:\t" + strings.Join(uid, "\t") + "\nGid:\t" + strings.Join(gid, "\t") + "\n"
			requireCode(t, checkIDs([]byte(data), 1234, 5678), api.CodeUnauthenticated)
		}
	}
	for _, data := range []string{"Uid: 1234\n", base + "Uid: 1234 1234 1234 1234\n", ""} {
		requireCode(t, checkIDs([]byte(data), 1234, 5678), api.CodeUnauthenticated)
	}
}

func TestUnifiedContainment(t *testing.T) {
	for _, group := range []string{"service/run", "other/run"} {
		got, err := unifiedGroup([]byte("0::/" + group + "\n"))
		if err != nil || got != group {
			t.Fatalf("kernel containment parsing failed: %v", err)
		}
	}
	for _, data := range []string{"", "1:cpu:/group\n", "0::/one\n0::/two\n", "bad"} {
		_, err := unifiedGroup([]byte(data))
		requireCode(t, err, api.CodeContainmentUnknown)
	}
}
