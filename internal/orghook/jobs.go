package orghook

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"laneboss.io/laneboss/internal/decisionsrv"
	"laneboss.io/laneboss/internal/guardtime"
	"laneboss.io/laneboss/internal/jobcatalog"
	"laneboss.io/laneboss/internal/judge"
)

const jobTag = "[laneboss-jobs]"

func currentJobCatalog(inst *instance) (map[string]any, error) {
	org, err := readBytes(filepath.Join(inst.home, "org.toml"), "job org sources")
	if err != nil {
		return nil, err
	}
	files := map[string]string{}
	count := 0
	for level := 3; level <= 6; level++ {
		relative := fmt.Sprintf("L%d/roles", level)
		path := filepath.Join(inst.home, relative)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, invalid("job role sources are unreadable")
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, invalid("job role sources are unreadable")
		}
		for _, entry := range entries {
			name := relative + "/" + entry.Name()
			if !jobcatalog.RoleSource(name) {
				continue
			}
			count++
			if count > 512 || entry.Type()&os.ModeSymlink != 0 {
				return nil, invalid("job role sources exceed their bounds or contain a symbolic link")
			}
			data, err := readBytes(filepath.Join(inst.home, name), "job role source")
			if err != nil || len(data) > 65536 {
				return nil, invalid("job role source is unreadable or too large")
			}
			files[name] = string(data)
		}
	}
	expected, err := jobcatalog.Build(org, files)
	if err != nil {
		return nil, err
	}
	raw, err := readBytes(filepath.Join(inst.home, jobcatalog.RelativePath), "job catalog")
	if err != nil || !jobcatalog.Matches(raw, expected) {
		return nil, invalid("job catalog is stale, missing or unreadable")
	}
	return expected, nil
}

// Only a baseline allowance reaches this function in a release. Job scoring
// never follows unavailable="refuse": a missing score adds a short notice.
func jobCall(inst *instance, act action, event map[string]any, runner, allowedReason string, parents ...context.Context) (bool, string, string, map[string]any) {
	parent := context.Background()
	if len(parents) > 0 {
		parent = parents[0]
	}
	ctx, cancel := context.WithTimeout(parent, guardtime.Timeout)
	defer cancel()
	if inst == nil || !contains(guardShellTools, act.tool) {
		return true, allowedReason, "", nil
	}
	g, err := decisionsrv.OpenGuide(inst.home)
	var settings decisionsrv.GuideSettings
	var present bool
	if err == nil {
		settings, present, err = g.Settings, g.Present, g.SettingsErr
	} else {
		settings, present, err = decisionsrv.ReadGuideSettings(inst.home)
	}
	if err != nil || !present || !settings.Enabled || !settings.Jobs {
		return true, allowedReason, "", nil
	}
	notice := func(outcome, text string) (bool, string, string, map[string]any) {
		return true, allowedReason, jobTag + " Baseline only: " + text + "; " + judge.JobTimeoutNotice() + ".",
			map[string]any{"band": "notice", "outcome": outcome, "judge": settings.Judge}
	}
	if settings.Judge == "" {
		return notice("unconfigured", "no job judge is configured")
	}
	catalog, err := currentJobCatalog(inst)
	if err != nil {
		return notice("stale-catalog", "the generated catalog is stale, missing or unreadable; ask the supervisor to render the org")
	}
	criteria, err := jobcatalog.Criteria(catalog)
	if err != nil {
		return notice("stale-catalog", "the generated catalog has no usable choices")
	}
	command := strings.TrimPrefix(guardActionText(event, runner, act), act.tool+": ")
	objects, managed, err := managedObjects(ctx, settings.Configuration, act)
	if err != nil {
		if ctx.Err() != nil {
			return notice("timeout", "the shared guard deadline expired")
		}
		return notice("unavailable", "the managed-object records could not be read")
	}
	state := map[string]any{}
	for key, value := range catalog {
		state[key] = value
	}
	state["managed_objects"] = objects
	var v judge.JobVerdict
	func() {
		defer func() {
			if recover() != nil {
				v, err = judge.JobVerdict{Verdict: judge.Verdict{Outcome: "refused"}}, nil
			}
		}()
		v, err = judge.AskJobsContext(ctx, settings.Configuration, settings.Judge, command, state)
	}()
	if err != nil {
		if ctx.Err() != nil {
			return notice("timeout", "the shared guard deadline expired")
		}
		return notice("unavailable", "the job judge could not be reached")
	}
	if v.Outcome != "answered" {
		return notice(v.Outcome, "the job judge gave no usable score ("+v.Outcome+")")
	}
	band := decisionsrv.BandNone
	if v.Probability >= settings.WarnAt {
		band = decisionsrv.BandWarn
	}
	if v.Command == "none" {
		band = decisionsrv.BandNone
	}
	if band == decisionsrv.BandWarn && v.Confidence < judge.JobConfidenceFloor {
		return true, allowedReason, fmt.Sprintf("%s Warning: the catalog route is uncertain (Choice confidence %.2f below %.2f); review the catalog before choosing a command.", jobTag, v.Confidence, judge.JobConfidenceFloor),
			map[string]any{"band": "uncertain", "outcome": v.Outcome, "judge": settings.Judge, "flagged": false, "laneboss_command": nil, "owned": v.Probability, "confidence": v.Confidence, "probabilities": v.Probabilities, "managed": managed}
	}
	flagged := band != decisionsrv.BandNone
	reason := ""
	var route any
	if flagged {
		route = v.Command
		reason = fmt.Sprintf("laneboss %s (%s) does this job; use it instead of the raw shell command", v.Command, strings.TrimRight(criteria[v.Command], "."))
	}
	note := map[string]any{"band": band.String(), "outcome": v.Outcome, "judge": settings.Judge,
		"flagged": flagged, "laneboss_command": route, "reason": reason, "owned": v.Probability, "confidence": v.Confidence, "probabilities": v.Probabilities, "managed": managed}
	switch band {
	case decisionsrv.BandWarn:
		return true, allowedReason, fmt.Sprintf("%s Warning: %s (owned probability %.2f, warn probability threshold %.2f).", jobTag, reason, v.Probability, settings.WarnAt), note
	}
	return true, allowedReason, "", note
}
