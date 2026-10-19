package claudock

import (
	"bufio"
	"bytes"
	"context"
	"reflect"
	"regexp"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) captured(ctx context.Context, record api.CaptureRecord) (api.RunnerRequest, []map[string]any, error) {
	var empty api.RunnerRequest
	if err := s.ready(ctx); err != nil {
		return empty, nil, err
	}
	if !identifier(record.ID) || !record.Primary || record.ReplacementOf != "" || record.Coverage != "complete" ||
		record.Offset < 0 || !blob(record.Data) || record.Stream != "stdout" && record.Stream != "vendor" && record.Stream != "structured" && record.Stream != "stderr" {
		return empty, nil, failure(api.CodeIntegrity, "capture must be complete primary outside output")
	}
	if _, valid := timestamp(record.ObservedAt); !valid {
		return empty, nil, failure(api.CodeInvalid, "capture observation time is invalid")
	}
	if _, err := s.primaryBinding(ctx, record); err != nil {
		return empty, nil, err
	}
	canonical, data, err := s.deps.Capture(ctx, record.ID)
	if err != nil {
		return empty, nil, dependency(err)
	}
	if canonical != record || int64(len(data)) != record.Data.Bytes || contentDigest(data) != record.Data.SHA256 {
		return empty, nil, failure(api.CodeIntegrity, "capture metadata or exact captured bytes differ from the protected spool")
	}
	request, err := s.boundRun(ctx, record.Target)
	if err != nil {
		return empty, nil, err
	}
	if err := s.mode(ctx, request); err != nil {
		return empty, nil, err
	}
	if record.Stream == "stderr" {
		// Stderr diagnostics are preserved, but neither text nor JSON printed
		// there is the selected stream-json provider envelope.
		return request, []map[string]any{}, nil
	}
	events := []map[string]any{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxRecordBytes)
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		event, err := decodeRecord(scanner.Bytes())
		if err != nil {
			return empty, nil, err
		}
		if !label(textValue(event["type"])) {
			return empty, nil, failure(api.CodeIntegrity, "captured vendor record has no event type")
		}
		if event["type"] == "result" {
			if _, ok := event["is_error"].(bool); !ok {
				return empty, nil, failure(api.CodeIntegrity, "captured result has no typed error flag")
			}
		}
		if id, exists := event["session_id"]; exists && id != request.Session.VendorID {
			return empty, nil, failure(api.CodeIntegrity, "captured vendor session differs from the protected run")
		}
		events = append(events, event)
		if len(events) > 65536 {
			return empty, nil, failure(api.CodeIntegrity, "structured capture exceeds the record-count bound")
		}
	}
	if scanner.Err() != nil {
		return empty, nil, failure(api.CodeIntegrity, "structured capture is incomplete or oversized")
	}
	return request, events, nil
}

func (s *Service) SessionFromCapture(ctx context.Context, record api.CaptureRecord) (api.Session, error) {
	request, events, err := s.captured(ctx, record)
	if err != nil {
		return api.Session{}, err
	}
	found := false
	for _, event := range events {
		if event["type"] != "system" || event["subtype"] != "init" {
			continue
		}
		if found || event["session_id"] != request.Session.VendorID || event["cwd"] != request.Session.LogicalCWD {
			return api.Session{}, failure(api.CodeIntegrity, "vendor init lost or duplicated its session/cwd binding")
		}
		found = true
	}
	if !found {
		return api.Session{}, failure(api.CodeNotFound, "primary capture has no vendor session init")
	}
	return request.Session, nil
}

func (s *Service) LimitFromCapture(ctx context.Context, record api.CaptureRecord, exit api.ProcessObservation) (*api.LimitSignal, error) {
	request, events, err := s.captured(ctx, record)
	if err != nil {
		return nil, err
	}
	observed, err := s.deps.Observation(ctx, record.Target)
	if err != nil {
		return nil, dependency(err)
	}
	if !reflect.DeepEqual(observed, exit) || exit.Handle.Target != record.Target || !terminalObservation(exit) || exit.ExitCode == nil {
		return nil, failure(api.CodeContainmentUnknown, "limit classification requires the exact exited zero-survivor observation")
	}
	ended, valid := timestamp(exit.ObservedAt)
	captured, _ := timestamp(record.ObservedAt)
	if !valid || ended.Before(captured) || int64(*exit.ExitCode) < -1<<31 || int64(*exit.ExitCode) > 1<<31-1 {
		return nil, failure(api.CodeIntegrity, "exit observation does not cover this capture")
	}
	kind := ""
	for _, event := range events {
		candidate, blocked := limitEvent(event, request.Session.VendorID)
		if blocked {
			return nil, nil
		}
		if candidate != "" {
			// A generic rejected rate notice can accompany the more specific
			// quota formatter. Preserve the most specific supported category.
			if kind == "" || kind == "rate_limit" || candidate == "session_limit" {
				kind = candidate
			}
		}
	}
	if kind == "" {
		return nil, nil
	}
	if s.deps.LimitGuard == nil {
		return nil, api.NotImplemented("lb-v2-lifecycle", "whole-run limit/refusal evidence")
	}
	profile, err := s.profile(ctx, request.Slot, false)
	if err != nil {
		return nil, err
	}
	usage, err := s.outsideUsage(ctx, request, profile, exit)
	if err != nil {
		return nil, err
	}
	if err := dependency(s.deps.LimitGuard(ctx, request, record, exit)); err != nil {
		return nil, err
	}
	code := *exit.ExitCode
	return &api.LimitSignal{Target: record.Target, Kind: kind, ProfileID: profile.ProfileID,
		Provider: profile.Provider, CaptureID: record.ID, CaptureSHA256: record.Data.SHA256,
		ExitCode: &code, AdapterVersion: AdapterVersion, ObservedAt: record.ObservedAt, UsageEvidence: &usage}, nil
}

// These exact wording families are sourced in docs/claudock.md from the native
// Claude Code 2.1.296 formatters. Wording alone is NEVER a production trigger;
// it must occur in a verified provider error envelope with a session binding.
var quotaHit = regexp.MustCompile(`^You['’]ve hit your (limit|usage limit|session limit|weekly limit|Opus limit|Sonnet limit)(?:[.!]| · (?:resets|limit resets) [^\r\n]+)?(?: · progress saved)?$`)
var quotaReached = regexp.MustCompile(`^Usage limit reached(?: · limit resets [^\r\n]+)?$`)

func quotaKind(message string) string {
	if strings.ContainsAny(message, "\r\n\x00") {
		return ""
	}
	if match := quotaHit.FindStringSubmatch(message); match != nil {
		if match[1] == "session limit" {
			return "session_limit"
		}
		return "usage_limit"
	}
	if quotaReached.MatchString(message) {
		return "usage_limit"
	}
	return ""
}

func limitEvent(event map[string]any, session string) (string, bool) {
	switch event["type"] {
	case "assistant":
		marker, hasError := event["error"]
		if !hasError || marker == "" || marker == nil {
			return "", false
		}
		if marker != "rate_limit" || event["session_id"] != session {
			return "", true
		}
		blocks, ok := object(event["message"])["content"].([]any)
		if !ok || len(blocks) != 1 || object(blocks[0])["type"] != "text" {
			return "", true
		}
		kind := quotaKind(textValue(object(blocks[0])["text"]))
		return kind, kind == ""
	case "result":
		if event["session_id"] != session {
			return "", true
		}
		if event["is_error"] != true {
			return "", true
		}
		subtype := ""
		if raw, exists := event["subtype"]; exists {
			var ok bool
			subtype, ok = raw.(string)
			if !ok {
				return "", true
			}
		}
		if subtype != "" && subtype != "success" && subtype != "error_during_execution" {
			return "", true
		}
		// docs/claudock.md and profile_swap/main.go describe both the result
		// string and errors array. Neither requires an invented error subtype.
		messages := []string{}
		if raw, exists := event["errors"]; exists {
			values, ok := raw.([]any)
			if !ok || len(values) == 0 {
				return "", true
			}
			for _, value := range values {
				message, ok := value.(string)
				if !ok {
					return "", true
				}
				messages = append(messages, message)
			}
		}
		if raw, exists := event["result"]; exists {
			result, ok := raw.(string)
			if !ok {
				return "", true
			}
			if result != "" {
				messages = append(messages, result)
			}
		}
		if len(messages) == 0 {
			return "", true
		}
		kind := ""
		for _, message := range messages {
			candidate := quotaKind(message)
			if candidate == "" {
				return "", true
			}
			if kind != "" && candidate != kind {
				return "", true
			}
			kind = candidate
		}
		return kind, false
	case "rate_limit_event":
		info := object(event["rate_limit_info"])
		if info["status"] != "rejected" {
			return "", false
		}
		if event["session_id"] != session {
			return "", true
		}
		// A rejected rate notice is a candidate until the outside run and
		// pinned-mode verifier above corroborate it. Fresh room is checked by
		// watchdog, never inferred here from model text or reset wording.
		return "rate_limit", false
	case "error":
		return "", true
	}
	return "", false
}
