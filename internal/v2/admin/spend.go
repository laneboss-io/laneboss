package admin

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

const maxBalanceOutput = 64 << 10

var balanceLine = regexp.MustCompile(`^([A-Za-z0-9_.-]+)[ \t]*:?[ \t]+\$?([0-9]+(?:\.[0-9]+)?)[ \t]*(?:USD)?$`)

// PoolReading selects exactly one complete balance line, never a number typed
// into the request. The raw stdout remains the private reconciliation evidence.
func PoolReading(reading api.SpendReading) (int64, error) {
	if !validID(reading.ID) || !validID(reading.CredentialID) || len(reading.ProfileIDs) == 0 || len(reading.ProfileIDs) > 128 ||
		reading.FloorMicros < 5000000 || reading.FloorMicros > 1<<53-1 || len(reading.Output) == 0 || len(reading.Output) > maxBalanceOutput ||
		!utf8.Valid(reading.Output) || bytes.ContainsRune(reading.Output, 0) || !validID(api.ID(reading.Selector)) {
		return 0, failure(api.CodeInvalid, "balance reading lacks its tool output, credential mapping or configured floor")
	}
	seen := map[api.ID]bool{}
	for _, id := range reading.ProfileIDs {
		if !validID(id) || seen[id] {
			return 0, failure(api.CodeInvalid, "balance reading profile mapping is invalid")
		}
		seen[id] = true
	}
	if at, err := time.Parse(time.RFC3339Nano, string(reading.ObservedAt)); err != nil || at.IsZero() {
		return 0, failure(api.CodeInvalid, "balance reading has no observation time")
	}
	found := false
	var amount int64
	for _, line := range strings.Split(string(reading.Output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		match := balanceLine.FindStringSubmatch(line)
		if match == nil {
			return 0, failure(api.CodeIntegrity, "balance tool emitted a malformed line")
		}
		if match[1] != reading.Selector {
			continue
		}
		if found {
			return 0, failure(api.CodeIntegrity, "balance tool duplicated the selected reading")
		}
		var err error
		amount, err = api.USDMicros(match[2], false)
		if err != nil {
			return 0, err
		}
		found = true
	}
	if !found {
		return 0, failure(api.CodePrerequisite, "balance tool omitted the selected reading")
	}
	return amount, nil
}

type boundedBalanceOutput struct{ bytes.Buffer }

func (b *boundedBalanceOutput) Write(data []byte) (int, error) {
	if len(data) > maxBalanceOutput-b.Len() {
		return 0, failure(api.CodeBudget, "balance tool output exceeds its bound")
	}
	return b.Buffer.Write(data)
}

// Reading runs only in the operator entry, before the administrator IPC call.
// Service handlers receive its bytes and never execute this command or claudock.
func (tool *BalanceTool) Reading(ctx context.Context) (api.SpendReading, error) {
	if tool == nil || !filepath.IsAbs(tool.Command) || filepath.Clean(tool.Command) != tool.Command {
		return api.SpendReading{}, failure(api.CodeInvalid, "balance tool requires a configured absolute executable")
	}
	info, err := os.Lstat(tool.Command)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
		return api.SpendReading{}, failure(api.CodePrerequisite, "balance tool executable is missing, linked or writable by others")
	}
	started := time.Now().UTC()
	call, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, tool.Command)
	var stdout boundedBalanceOutput
	cmd.Stdout, cmd.Stderr = &stdout, io.Discard
	if err := cmd.Run(); err != nil {
		return api.SpendReading{}, failure(api.CodeUnavailable, "balance tool failed; no reading was enrolled")
	}
	id, err := randomID("balance-")
	if err != nil {
		return api.SpendReading{}, err
	}
	reading := api.SpendReading{ID: id, CredentialID: tool.CredentialID, ProfileIDs: append([]api.ID{}, tool.ProfileIDs...), FloorMicros: tool.FloorMicros,
		Selector: tool.Selector, Output: bytes.Clone(stdout.Bytes()), ObservedAt: api.Timestamp(started.Format(time.RFC3339Nano))}
	if _, err := PoolReading(reading); err != nil {
		return api.SpendReading{}, err
	}
	return reading, nil
}

type spendChannelKey struct{}
type spendChannel struct {
	endpoint api.AdminEnrollmentEndpoint
	reading  api.SpendReading
}

func bindSpendReading(ctx context.Context, endpoint api.AdminEnrollmentEndpoint, reading api.SpendReading) (context.Context, error) {
	if err := CheckEnrollmentChannel(ctx, endpoint); err != nil {
		return nil, err
	}
	if _, err := PoolReading(reading); err != nil {
		return nil, err
	}
	reading.Output = bytes.Clone(reading.Output)
	reading.ProfileIDs = append([]api.ID{}, reading.ProfileIDs...)
	return context.WithValue(ctx, spendChannelKey{}, spendChannel{endpoint, reading}), nil
}

// CheckSpendReading is the writer's narrow native-admin capability check.
// Serialized scopes, actor labels and copied output confer no authority.
func CheckSpendReading(ctx context.Context, reading api.SpendReading) (string, error) {
	channel, ok := ctx.Value(spendChannelKey{}).(spendChannel)
	if !ok || !reflect.DeepEqual(channel.reading, reading) {
		return "", failure(api.CodeForbidden, "spend reconciliation requires its exact native administrator reading")
	}
	if err := CheckEnrollmentChannel(ctx, channel.endpoint); err != nil {
		return "", err
	}
	return channel.endpoint.Config, nil
}
