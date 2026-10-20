package dashboard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/objectread"
)

func wrapStoreErr(err error, msg string) error {
	if err == nil {
		return nil
	}
	var typed *api.Error
	if errors.As(err, &typed) {
		return typed
	}
	return unavailableErr(msg, "Verify the service store and retry.")
}

func isActiveLaneState(state string, cleaned bool) bool {
	if cleaned {
		return false
	}
	switch state {
	case "preparing", "running", "stopping", "profile_wait", "idle":
		return true
	default:
		return false
	}
}

func matchesTimeBounds(ts api.Timestamp, q api.DashboardQuery) bool {
	if q.Since == "" && q.Until == "" {
		return true
	}
	t, err := parseTimestamp(ts)
	if err != nil {
		return false
	}
	if q.Since != "" {
		sinceT, err := parseTimestamp(q.Since)
		if err == nil && t.Before(sinceT) {
			return false
		}
	}
	if q.Until != "" {
		untilT, err := parseTimestamp(q.Until)
		if err == nil && t.After(untilT) {
			return false
		}
	}
	return true
}

func (s *Service) readAllLanes(ctx context.Context, scope api.Scope, lifeID api.ID) ([]api.Lane, error) {
	var all []api.Lane
	cursor := ""
	seenCursors := make(map[string]bool)
	for {
		page, err := s.deps.Store.Lanes(ctx, scope, api.ListRequest{
			LifeID: lifeID,
			Cursor: cursor,
			Limit:  maxPageLimit,
		})
		if err != nil {
			return nil, wrapStoreErr(err, "lane projections are unavailable")
		}
		all = append(all, page.Lanes...)
		if page.Cursor == "" {
			break
		}
		if len(page.Lanes) == 0 || seenCursors[page.Cursor] {
			return nil, integrityErr("lane pagination did not advance", "Inspect the pinned store inventory.")
		}
		seenCursors[page.Cursor] = true
		cursor = page.Cursor
	}
	return all, nil
}

func (s *Service) readAllMail(ctx context.Context, scope api.Scope, lifeID api.ID) ([]api.Mail, error) {
	var all []api.Mail
	seen := make(map[string]bool)
	cursor := ""
	for {
		page, err := s.deps.Store.Mail(ctx, scope, api.ListRequest{LifeID: lifeID, Limit: maxPageLimit, Cursor: cursor})
		if err != nil {
			return nil, wrapStoreErr(err, "mail projection is unavailable")
		}
		all = append(all, page.Messages...)
		if page.Cursor == "" {
			return all, nil
		}
		if len(page.Messages) == 0 || seen[page.Cursor] {
			return nil, integrityErr("mail pagination did not advance", "Inspect the pinned store inventory.")
		}
		seen[page.Cursor], cursor = true, page.Cursor
	}
}

func (s *Service) readAllRecords(ctx context.Context, scope api.Scope, collection string) ([]api.Record, error) {
	var all []api.Record
	seen := make(map[string]bool)
	cursor := ""
	for {
		page, err := s.deps.Store.Records(ctx, scope, api.RecordQuery{Collection: collection, SearchMode: "keyword", Limit: maxPageLimit, Cursor: cursor})
		if err != nil {
			return nil, wrapStoreErr(err, "record inventory is unavailable")
		}
		all = append(all, page.Records...)
		if page.Cursor == "" {
			return all, nil
		}
		if len(page.Records) == 0 || seen[page.Cursor] {
			return nil, integrityErr("record pagination did not advance", "Inspect the pinned store inventory.")
		}
		seen[page.Cursor], cursor = true, page.Cursor
	}
}

func (s *Service) readAllEvents(ctx context.Context, scope api.Scope, lifeID api.ID, run api.RunNumber) ([]api.Event, error) {
	var all []api.Event
	var since api.Sequence
	for {
		page, err := s.deps.Store.Events(ctx, scope, api.EventTailRequest{
			LifeID: lifeID,
			Run:    run,
			Since:  since,
			Follow: false,
		})
		if err != nil {
			return nil, wrapStoreErr(err, "event log is unavailable")
		}
		if len(page.Events) == 0 {
			if !page.Complete {
				return nil, integrityErr("event pagination did not advance", "Inspect the pinned event inventory.")
			}
			break
		}
		maxSeq := since
		for _, ev := range page.Events {
			all = append(all, ev)
			if ev.Seq > maxSeq {
				maxSeq = ev.Seq
			}
		}
		if page.Complete {
			break
		}
		if maxSeq <= since {
			return nil, integrityErr("event pagination did not advance", "Inspect the pinned event inventory.")
		}
		since = maxSeq
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].Seq < all[j].Seq
	})
	return all, nil
}

// Historical views retain every run represented by each visible lane. Each
// lookup still selects one exact life/run and keeps the caller's read scope.
func (s *Service) readLaneEvents(ctx context.Context, scope api.Scope, lanes []api.Lane) ([]api.Event, error) {
	var all []api.Event
	for _, lane := range lanes {
		if !validID(lane.LifeID) || lane.Run == 0 || lane.Run > maxSafeInt {
			return nil, integrityErr("lane projection lacks an exact event selection", "Inspect the committed lane inventory.")
		}
		for run := api.RunNumber(1); run <= lane.Run; run++ {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			events, err := s.readAllEvents(ctx, scope, lane.LifeID, run)
			if err != nil {
				return nil, err
			}
			all = append(all, events...)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Seq < all[j].Seq })
	return all, nil
}

func (s *Service) readVerifiedBlob(ctx context.Context, scope api.Scope, ref api.BlobRef) (resultBytes []byte, resultErr error) {
	if ref.ID == "" || !validID(ref.ID) {
		return nil, invalidErr("invalid blob reference id", "Reference a committed blob object.")
	}
	if !validDigest(ref.SHA256) {
		return nil, invalidErr("invalid blob sha256 digest", "Reference a committed blob digest.")
	}
	if ref.Bytes < 0 || ref.Bytes > api.MaxObjectBytes {
		return nil, invalidErr("blob size out of bounds", "Keep object sizes within 64 MiB.")
	}
	scope, release, err := objectread.Bind(ctx, s.deps.Store, scope)
	if err != nil {
		return nil, wrapStoreErr(err, "blob object read view is unavailable")
	}
	defer release(&resultErr)
	if meta, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID); err == nil {
		if meta.Ref.SHA256 != "" && meta.Ref.SHA256 != ref.SHA256 {
			return nil, integrityErr("blob metadata digest mismatch", "Verify committed object metadata.")
		}
		if meta.Ref.Bytes > 0 && meta.Ref.Bytes != ref.Bytes {
			return nil, integrityErr("blob metadata size mismatch", "Verify committed object metadata.")
		}
		if meta.Ref.Class != "" && ref.Class != "" && meta.Ref.Class != ref.Class {
			return nil, forbiddenErr("blob class label does not match committed object metadata", "Use the service-assigned blob class.")
		}
	} else {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
			return nil, wrapStoreErr(err, "blob object metadata is unavailable")
		}
	}
	var out []byte
	var offset int64
	for offset < ref.Bytes || (ref.Bytes == 0 && offset == 0) {
		limit := api.MaxChunkBytes
		if rem := int(ref.Bytes - offset); rem > 0 && rem < limit {
			limit = rem
		}
		chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{
			ObjectID: ref.ID,
			Offset:   offset,
			Limit:    limit,
		})
		if err != nil {
			return nil, wrapStoreErr(err, "blob object could not be read")
		}
		out = append(out, chunk.Data...)
		if ref.Bytes == 0 || len(chunk.Data) == 0 {
			break
		}
		offset += int64(len(chunk.Data))
	}
	sum := sha256.Sum256(out)
	if api.Digest(hex.EncodeToString(sum[:])) != ref.SHA256 {
		return nil, integrityErr("stored blob content hash mismatch", "Run laneboss store verify and preserve state evidence.")
	}
	return out, nil
}

// reconcileLanes applies committed service-origin lifecycle events on top of
// Store.Lanes so lifecycle and tree views converge immediately and ignore non-service observations.
func reconcileLanes(lanes []api.Lane, events []api.Event) ([]api.Lane, map[api.ID]api.Lane, map[api.ID]api.Timestamp, api.Sequence) {
	byID := make(map[api.ID]api.Lane, len(lanes))
	order := make([]api.ID, 0, len(lanes))
	lastTime := make(map[api.ID]api.Timestamp, len(lanes))
	lastTimeSeq := make(map[api.ID]api.Sequence, len(lanes))
	observeLaneTime := func(lifeID api.ID, ev api.Event) {
		if lifeID == "" || ev.Seq < lastTimeSeq[lifeID] {
			return
		}
		if _, err := parseTimestamp(ev.RecordedAt); err != nil {
			return
		}
		lastTime[lifeID], lastTimeSeq[lifeID] = ev.RecordedAt, ev.Seq
	}
	var maxSeq api.Sequence

	for _, l := range lanes {
		if l.LifeID == "" {
			continue
		}
		if l.StarterChain == nil {
			l.StarterChain = []api.ID{}
		}
		byID[l.LifeID] = l
		order = append(order, l.LifeID)
		if l.LastSeq > maxSeq {
			maxSeq = l.LastSeq
		}
	}

	for _, ev := range events {
		if ev.Seq > maxSeq {
			maxSeq = ev.Seq
		}
		// Only trusted service-origin events may create or mutate lifecycle projections.
		if ev.Origin != "service" {
			continue
		}
		// Observation time follows the latest timestamped event, independently
		// of a newer state snapshot's revision. Unknown times stay unknown.
		observeLaneTime(ev.LifeID, ev)
		switch ev.Kind {
		case "lane.created", "lane.adopted", "launch.prepared", "lane.started", "lane.resumed":
			var le api.LaunchEvent
			if json.Unmarshal(ev.Payload, &le) != nil || le.Lane.LifeID == "" {
				continue
			}
			if ev.LifeID == "" {
				observeLaneTime(le.Lane.LifeID, ev)
			}
			cur, exists := byID[le.Lane.LifeID]
			if !exists {
				order = append(order, le.Lane.LifeID)
			}
			if !exists || ev.Seq >= cur.LastSeq {
				next := le.Lane
				if next.StarterChain == nil {
					next.StarterChain = []api.ID{}
				}
				if ev.ParentLifeID != "" {
					next.ParentLifeID = ev.ParentLifeID
				}
				if ev.RootLifeID != "" {
					next.RootLifeID = ev.RootLifeID
				}
				switch ev.Kind {
				case "lane.created", "launch.prepared":
					next.State = "preparing"
				case "lane.started", "lane.resumed":
					next.State = "running"
				}
				next.LastSeq = ev.Seq
				byID[next.LifeID] = next
			}
		case "lane.stopping":
			if ev.LifeID == "" {
				continue
			}
			cur, exists := byID[ev.LifeID]
			if !exists || ev.Seq < cur.LastSeq {
				continue
			}
			var se api.StateEvent
			if json.Unmarshal(ev.Payload, &se) == nil {
				cur.State = "stopping"
				if se.Generation != 0 {
					cur.Generation = se.Generation
				}
				cur.LastSeq = ev.Seq
				byID[ev.LifeID] = cur
			}
		case "lane.ended":
			if ev.LifeID == "" {
				continue
			}
			cur, exists := byID[ev.LifeID]
			if !exists || ev.Seq < cur.LastSeq {
				continue
			}
			var re api.RunEndEvent
			if json.Unmarshal(ev.Payload, &re) == nil {
				if re.Observation.State == "unknown" || re.Observation.Survivors == nil || *re.Observation.Survivors > 0 {
					cur.State = "lost"
				} else if re.ProfileContinuation {
					cur.State = "profile_wait"
				} else {
					cur.State = "verifying"
				}
				cur.BudgetRemaining = re.BudgetRemaining
				cur.LastSeq = ev.Seq
				byID[ev.LifeID] = cur
			}
		case "lane.lost":
			if ev.LifeID == "" {
				continue
			}
			cur, exists := byID[ev.LifeID]
			if !exists || ev.Seq < cur.LastSeq {
				continue
			}
			cur.State = "lost"
			cur.LastSeq = ev.Seq
			byID[ev.LifeID] = cur
		case "lane.state":
			if ev.LifeID == "" {
				continue
			}
			cur, exists := byID[ev.LifeID]
			if !exists || ev.Seq < cur.LastSeq {
				continue
			}
			var se api.StateEvent
			if json.Unmarshal(ev.Payload, &se) == nil && se.To != "" {
				cur.State = se.To
				if se.Generation != 0 {
					cur.Generation = se.Generation
				}
				cur.LastSeq = ev.Seq
				byID[ev.LifeID] = cur
			}
		case "lane.policy":
			cur, exists := byID[ev.LifeID]
			if !exists || ev.Seq <= cur.LastSeq {
				continue
			}
			var policy api.PolicyAdvanceEvent
			if api.DecodeObject(ev.Payload, &policy) != nil || policy.FromGeneration != cur.PolicyGeneration ||
				policy.ToGeneration <= policy.FromGeneration || policy.LaneGeneration != cur.Generation+1 ||
				policy.GrantSetID != cur.GrantSetID {
				continue
			}
			cur.PolicyGeneration = policy.ToGeneration
			cur.Generation = policy.LaneGeneration
			cur.LastSeq = ev.Seq
			byID[ev.LifeID] = cur
		case "lane.cleaned":
			if ev.LifeID == "" {
				continue
			}
			cur, exists := byID[ev.LifeID]
			if !exists || ev.Seq < cur.LastSeq {
				continue
			}
			cur.Cleaned = true
			cur.LastSeq = ev.Seq
			byID[ev.LifeID] = cur
		}
	}

	sort.Slice(order, func(i, j int) bool {
		li, lj := byID[order[i]], byID[order[j]]
		if li.StarterEventSeq != lj.StarterEventSeq {
			return li.StarterEventSeq < lj.StarterEventSeq
		}
		return li.LifeID < lj.LifeID
	})
	out := make([]api.Lane, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out, byID, lastTime, maxSeq
}

func parseInstanceSource(src api.SourceRef) (api.TreeNode, bool) {
	p := strings.TrimPrefix(src.Path, "/")
	parts := strings.Split(p, "/")
	if len(parts) >= 2 && (parts[0] == "instances" || parts[0] == "roles") {
		name := strings.TrimSuffix(parts[1], ".toml")
		name = strings.TrimSuffix(name, ".json")
		level := 3
		role := name
		if len(name) >= 3 && name[0] == 'L' && name[2] == '-' && name[1] >= '3' && name[1] <= '6' {
			level = int(name[1] - '0')
			role = name[3:]
		}
		id := src.ID
		if id == "" {
			id = api.ID(name)
		}
		return api.TreeNode{
			InstanceID: id,
			Level:      level,
			Role:       role,
			State:      "configured",
			Configured: true,
			Live:       false,
		}, true
	}
	return api.TreeNode{}, false
}

func (s *Service) configuredTreeNodes(ctx context.Context, scope api.Scope) ([]api.TreeNode, error) {
	byInst := make(map[api.ID]api.TreeNode)
	var order []api.ID
	addNode := func(n api.TreeNode) {
		if n.InstanceID == "" {
			return
		}
		if _, exists := byInst[n.InstanceID]; !exists {
			order = append(order, n.InstanceID)
		}
		n.Configured = true
		n.Live = false
		if n.State == "" {
			n.State = "configured"
		}
		byInst[n.InstanceID] = n
	}

	pol, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
			return nil, wrapStoreErr(err, "policy sources are unavailable")
		}
	} else {
		if pol.Context.InstanceID != "" && pol.Context.Level >= 3 && pol.Context.Level <= 6 {
			addNode(api.TreeNode{
				InstanceID: pol.Context.InstanceID,
				Level:      pol.Context.Level,
				Role:       pol.Context.Role,
				State:      "configured",
			})
		}
		for _, src := range pol.Sources {
			if n, ok := parseInstanceSource(src); ok {
				addNode(n)
			}
		}
	}

	sort.Slice(order, func(i, j int) bool {
		return order[i] < order[j]
	})
	out := make([]api.TreeNode, 0, len(order))
	for _, id := range order {
		if n, ok := byInst[id]; ok {
			out = append(out, n)
		}
	}
	return out, nil
}

func (s *Service) DashboardTree(ctx context.Context, scope api.Scope, request api.DashboardQuery) (api.TreeView, error) {
	var empty api.TreeView
	var err error
	scope, err = s.currentHumanScope(ctx, scope)
	if err != nil {
		return empty, err
	}
	if err := validateQuery(request); err != nil {
		return empty, err
	}
	rawLanes, err := s.readAllLanes(ctx, scope, "")
	if err != nil {
		return empty, err
	}
	visible := make([]api.Lane, 0, len(rawLanes))
	for _, lane := range rawLanes {
		if request.LifeID != "" && lane.LifeID != request.LifeID && lane.ParentLifeID != request.LifeID ||
			request.Level != 0 && lane.Level != request.Level || request.Driver != "" && lane.Session.Driver != request.Driver {
			continue
		}
		visible = append(visible, lane)
	}
	rawLanes = visible
	// The visible lane inventory selects each life and its current run before
	// reading events. A human tree request is not an unscoped journal reader.
	var events []api.Event
	for _, lane := range rawLanes {
		if !validID(lane.LifeID) || lane.Run == 0 {
			return empty, integrityErr("lane projection lacks an exact event selection", "Inspect the committed lane inventory.")
		}
		selected, err := s.readAllEvents(ctx, scope, lane.LifeID, lane.Run)
		if err != nil {
			return empty, err
		}
		events = append(events, selected...)
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Seq < events[j].Seq })
	cfgNodes, err := s.configuredTreeNodes(ctx, scope)
	if err != nil {
		return empty, err
	}
	lanes, _, lastTime, lastSeq := reconcileLanes(rawLanes, events)
	offset, err := s.decodeCursor(scope, "dashboard.tree", request, api.Generation(lastSeq))
	if err != nil {
		return empty, err
	}

	cfgByID := make(map[api.ID]bool, len(cfgNodes))
	for _, cn := range cfgNodes {
		cfgByID[cn.InstanceID] = true
	}

	var matched []api.TreeNode
	for _, cn := range cfgNodes {
		if request.LifeID != "" || request.Run != 0 || request.Driver != "" || request.Since != "" || request.Until != "" {
			continue
		}
		if request.Level != 0 && cn.Level != request.Level {
			continue
		}
		matched = append(matched, cn)
	}

	for _, l := range lanes {
		if request.LifeID != "" && l.LifeID != request.LifeID && l.ParentLifeID != request.LifeID {
			continue
		}
		if request.Run != 0 && l.Run != request.Run {
			continue
		}
		if request.Level != 0 && l.Level != request.Level {
			continue
		}
		if request.Driver != "" && l.Session.Driver != request.Driver {
			continue
		}
		if ts := lastTime[l.LifeID]; !matchesTimeBounds(ts, request) {
			continue
		}
		instID := api.ID("")
		if cfgByID[api.ID(l.Name)] {
			instID = api.ID(l.Name)
		}
		matched = append(matched, api.TreeNode{
			InstanceID:   instID,
			LifeID:       l.LifeID,
			ParentLifeID: l.ParentLifeID,
			Level:        l.Level,
			Role:         l.Role,
			State:        l.State,
			Configured:   instID != "",
			Live:         isActiveLaneState(l.State, l.Cleaned),
		})
	}

	if offset > len(matched) {
		offset = len(matched)
	}
	end := offset + request.Limit
	nextCursor := ""
	if end < len(matched) {
		nextCursor = s.encodeCursor(scope, "dashboard.tree", request, end, api.Generation(lastSeq))
	} else {
		end = len(matched)
	}
	page := matched[offset:end]
	if page == nil {
		page = []api.TreeNode{}
	}
	return api.TreeView{
		Nodes:   page,
		LastSeq: lastSeq,
		Cursor:  nextCursor,
	}, nil
}

func (s *Service) DashboardRaw(ctx context.Context, scope api.Scope, request api.DashboardQuery) (api.RawView, error) {
	var empty api.RawView
	var err error
	scope, err = s.currentHumanScope(ctx, scope)
	if err != nil {
		return empty, err
	}
	if err := validateQuery(request); err != nil {
		return empty, err
	}
	offset, err := s.decodeCursor(scope, "dashboard.raw", request, 0)
	if err != nil {
		return empty, err
	}
	rawLanes, err := s.readAllLanes(ctx, scope, "")
	if err != nil {
		return empty, err
	}
	// Reconcile raw-view metadata across every run before filtering.
	events, err := s.readLaneEvents(ctx, scope, rawLanes)
	if err != nil {
		return empty, err
	}
	_, laneByID, _, _ := reconcileLanes(rawLanes, events)

	// Read mail from Store.Mail as well as service-origin events.
	mail, err := s.readAllMail(ctx, scope, request.LifeID)
	if err != nil {
		return empty, wrapStoreErr(err, "mail projection is unavailable")
	}

	lifeMatches := func(lifeID api.ID) bool {
		if request.LifeID != "" && lifeID != request.LifeID {
			return false
		}
		if request.Level != 0 || request.Driver != "" {
			l, ok := laneByID[lifeID]
			if !ok {
				return false
			}
			if request.Level != 0 && l.Level != request.Level {
				return false
			}
			if request.Driver != "" && l.Session.Driver != request.Driver {
				return false
			}
		}
		return true
	}

	var records []api.CaptureRecord
	var gaps []api.CaptureGap
	primaryByID := make(map[api.ID]api.CaptureRecord)
	mailByID := make(map[api.ID]api.Mail)
	mailTime := make(map[api.ID]api.Timestamp)
	terminalMail := make(map[api.ID]string)
	var mailOrder []api.ID

	for _, m := range mail {
		if m.ID == "" {
			continue
		}
		mailByID[m.ID] = m
		if m.Status == "delivered" || m.Status == "returned" {
			terminalMail[m.ID] = m.Status
		}
		mailOrder = append(mailOrder, m.ID)
	}

	for _, ev := range events {
		// Ignore any non-service observation so lane-authored records cannot overwrite primary capture or mail.
		if ev.Origin != "service" {
			continue
		}
		switch ev.Kind {
		case "capture.refused":
			var binding api.CaptureBinding
			if json.Unmarshal(ev.Payload, &binding) != nil || binding.Status != "refused" || binding.Refusal == nil {
				continue
			}
			if binding.Config != scope.Config || !lifeMatches(binding.Target.LifeID) ||
				request.Run != 0 && binding.Target.Run != request.Run || !matchesTimeBounds(ev.RecordedAt, request) {
				continue
			}
			// The refused binding advertises no captured bytes or producer.
			// Both required primary streams have unknown end offsets.
			for _, stream := range []string{"stdout", "stderr"} {
				gaps = append(gaps, api.CaptureGap{BindingID: binding.ID, Target: binding.Target, Stream: stream,
					Reason: "capture_refused:" + string(binding.Refusal.Code), ObservedAt: ev.RecordedAt})
			}
		case "capture.appended":
			var rec api.CaptureRecord
			if json.Unmarshal(ev.Payload, &rec) != nil || rec.ID == "" {
				continue
			}
			if rec.Primary && rec.Data.Class != "capture" {
				// A non-capture blob class cannot masquerade as primary capture.
				rec.Primary = false
			}
			if rec.Primary {
				primaryByID[rec.ID] = rec
			} else if rec.ReplacementOf != "" {
				// Supplementary transcript replacement never deletes or overwrites primaryByID[rec.ReplacementOf].
				_ = primaryByID[rec.ReplacementOf]
			}
			if !lifeMatches(rec.Target.LifeID) {
				continue
			}
			if request.Run != 0 && rec.Target.Run != request.Run {
				continue
			}
			if !matchesTimeBounds(rec.ObservedAt, request) {
				continue
			}
			records = append(records, rec)
			if rec.Primary && (rec.Coverage == "partial" || rec.Coverage == "missing" || rec.Coverage == "unsupported") {
				startOff := rec.Offset + rec.Data.Bytes
				gaps = append(gaps, api.CaptureGap{
					Target:      rec.Target,
					Stream:      rec.Stream,
					StartOffset: startOff,
					Reason:      "incomplete_coverage:" + rec.Coverage,
					ObservedAt:  rec.ObservedAt,
				})
			}
		case "capture.gap":
			var gap api.CaptureGap
			if json.Unmarshal(ev.Payload, &gap) != nil {
				continue
			}
			if !lifeMatches(gap.Target.LifeID) {
				continue
			}
			if request.Run != 0 && gap.Target.Run != request.Run {
				continue
			}
			if !matchesTimeBounds(gap.ObservedAt, request) {
				continue
			}
			gaps = append(gaps, gap)
		case "mail.queued", "report.submitted":
			var m api.Mail
			if json.Unmarshal(ev.Payload, &m) != nil || m.ID == "" {
				continue
			}
			if _, exists := mailByID[m.ID]; !exists {
				mailOrder = append(mailOrder, m.ID)
			}
			if status := terminalMail[m.ID]; status != "" {
				m.Status = status
			}
			mailByID[m.ID] = m
			mailTime[m.ID] = ev.RecordedAt
		case "mail.delivered", "mail.returned":
			var mr api.MailReceipt
			if json.Unmarshal(ev.Payload, &mr) != nil || mr.MailID == "" {
				continue
			}
			if cur, exists := mailByID[mr.MailID]; exists {
				cur.Status = mr.Status
				if status := terminalMail[mr.MailID]; status != "" {
					cur.Status = status
				}
				mailByID[mr.MailID] = cur
			}
		}
	}

	// Detect byte-range discontinuities in primary capture streams so no capture gap can be hidden.
	type streamKey struct {
		life   api.ID
		run    api.RunNumber
		stream string
	}
	streamRecs := make(map[streamKey][]api.CaptureRecord)
	for _, r := range records {
		if r.Primary {
			k := streamKey{r.Target.LifeID, r.Target.Run, r.Stream}
			streamRecs[k] = append(streamRecs[k], r)
		}
	}
	for k, list := range streamRecs {
		sort.Slice(list, func(i, j int) bool {
			return list[i].Offset < list[j].Offset
		})
		var expected int64
		for _, r := range list {
			if r.Offset > expected {
				endOff := r.Offset
				alreadyRecorded := false
				for _, g := range gaps {
					if g.Target.LifeID == k.life && g.Target.Run == k.run && g.Stream == k.stream && g.StartOffset == expected {
						alreadyRecorded = true
						break
					}
				}
				if !alreadyRecorded {
					gaps = append(gaps, api.CaptureGap{
						Target:      r.Target,
						Stream:      r.Stream,
						StartOffset: expected,
						EndOffset:   &endOff,
						Reason:      "offset_discontinuity",
						ObservedAt:  r.ObservedAt,
					})
				}
			}
			if next := r.Offset + r.Data.Bytes; next > expected {
				expected = next
			}
		}
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].Target.LifeID != records[j].Target.LifeID {
			return records[i].Target.LifeID < records[j].Target.LifeID
		}
		if records[i].Target.Run != records[j].Target.Run {
			return records[i].Target.Run < records[j].Target.Run
		}
		if records[i].Stream != records[j].Stream {
			return records[i].Stream < records[j].Stream
		}
		if records[i].Offset != records[j].Offset {
			return records[i].Offset < records[j].Offset
		}
		return records[i].ID < records[j].ID
	})

	sort.Slice(gaps, func(i, j int) bool {
		if gaps[i].Target.LifeID != gaps[j].Target.LifeID {
			return gaps[i].Target.LifeID < gaps[j].Target.LifeID
		}
		if gaps[i].Target.Run != gaps[j].Target.Run {
			return gaps[i].Target.Run < gaps[j].Target.Run
		}
		if gaps[i].Stream != gaps[j].Stream {
			return gaps[i].Stream < gaps[j].Stream
		}
		return gaps[i].StartOffset < gaps[j].StartOffset
	})

	var messages []api.Mail
	for _, id := range mailOrder {
		m := mailByID[id]
		if request.LifeID != "" && m.RecipientLifeID != request.LifeID && m.Sender.LifeID != request.LifeID {
			continue
		}
		if request.Level != 0 || request.Driver != "" {
			matched := false
			if m.RecipientLifeID != "" && lifeMatches(m.RecipientLifeID) {
				matched = true
			}
			if !matched && m.Sender.LifeID != "" && lifeMatches(m.Sender.LifeID) {
				matched = true
			}
			if !matched && request.Driver == "" && m.Sender.Level == request.Level {
				matched = true
			}
			if !matched {
				continue
			}
		}
		if ts := mailTime[id]; !matchesTimeBounds(ts, request) {
			continue
		}
		if m.Artifacts == nil {
			m.Artifacts = []api.BlobRef{}
		}
		messages = append(messages, m)
	}
	sort.Slice(messages, func(i, j int) bool {
		if messages[i].QueuedSeq != messages[j].QueuedSeq {
			return messages[i].QueuedSeq < messages[j].QueuedSeq
		}
		return messages[i].ID < messages[j].ID
	})

	nextCursor := ""
	if offset > len(records) {
		offset = len(records)
	}
	end := offset + request.Limit
	if end < len(records) {
		nextCursor = s.encodeCursor(scope, "dashboard.raw", request, end, 0)
	} else {
		end = len(records)
	}
	pagedRecords := records[offset:end]
	if pagedRecords == nil {
		pagedRecords = []api.CaptureRecord{}
	}
	if messages == nil {
		messages = []api.Mail{}
	}
	if gaps == nil {
		gaps = []api.CaptureGap{}
	}
	return api.RawView{
		Records:  pagedRecords,
		Messages: messages,
		Gaps:     gaps,
		Cursor:   nextCursor,
	}, nil
}

func isAuthoritativeDecisionRecord(rec api.Record) bool {
	if rec.Collection != "decisions" || rec.Origin != "service" {
		return false
	}
	switch rec.Actor.Kind {
	case "human", "service":
		return true
	case "lane":
		return rec.Actor.Level == 6
	default:
		return false
	}
}

func normalizeDecisionCandidate(cand api.DecisionCandidate, rec api.Record) api.DecisionCandidate {
	if cand.ID == "" {
		cand.ID = rec.ID
	}
	if cand.EffectiveAt == "" {
		cand.EffectiveAt = rec.RecordedAt
	}
	if cand.Source.ID == "" {
		cand.Source.ID = rec.Content.ID
	}
	if cand.Source.Path == "" {
		cand.Source.Path = "decisions/" + string(rec.ID)
	}
	if cand.Source.SHA256 == "" {
		cand.Source.SHA256 = rec.Content.SHA256
	}
	if cand.Source.Generation == 0 {
		cand.Source.Generation = rec.Generation
	}
	if cand.Authority.Kind == "" {
		if rec.Actor.Kind == "lane" && rec.Actor.Level == 6 {
			cand.Authority.Kind = "d6"
		} else if rec.Actor.Kind != "" {
			cand.Authority.Kind = rec.Actor.Kind
		} else {
			cand.Authority.Kind = "human"
		}
	}
	if cand.Authority.ReceiptID == "" {
		cand.Authority.ReceiptID = rec.ID
	}
	if cand.Authority.OrgGeneration == 0 {
		cand.Authority.OrgGeneration = rec.Generation
	}
	if cand.AppliesTo.Levels == nil {
		cand.AppliesTo.Levels = []int{}
	}
	if cand.AppliesTo.Roles == nil {
		cand.AppliesTo.Roles = []string{}
	}
	if cand.AppliesTo.ProjectIDs == nil {
		cand.AppliesTo.ProjectIDs = []api.ID{}
	}
	if cand.AppliesTo.LifeIDs == nil {
		cand.AppliesTo.LifeIDs = []api.ID{}
	}
	cand.Text = screenString(cand.Text)
	return cand
}

func (s *Service) decodeDecisionRecord(ctx context.Context, scope api.Scope, rec api.Record) (api.DecisionCandidate, error) {
	raw, err := s.readVerifiedBlob(ctx, scope, rec.Content)
	if err != nil {
		return api.DecisionCandidate{}, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return api.DecisionCandidate{}, invalidErr("decision text is empty", "Provide nonempty decision text.")
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		var doc api.DecisionDocument
		if err := api.DecodeObject(raw, &doc); err == nil {
			if doc.Schema != "laneboss.decision.v2" || strings.TrimSpace(doc.Text) == "" {
				return api.DecisionCandidate{}, invalidErr("invalid structured decision schema or text", "Use schema laneboss.decision.v2 with nonempty text.")
			}
			if _, err := parseTimestamp(doc.EffectiveAt); err != nil {
				return api.DecisionCandidate{}, invalidErr("invalid decision effective_at timestamp", "Use RFC3339Nano UTC ending with Z.")
			}
			app := doc.AppliesTo
			if len(app.Levels)+len(app.Roles)+len(app.ProjectIDs)+len(app.LifeIDs) > 200 {
				return api.DecisionCandidate{}, invalidErr("decision applicability exceeds 200 entries", "Bound applicability entries to at most 200.")
			}
			for _, lvl := range app.Levels {
				if lvl < 3 || lvl > 6 {
					return api.DecisionCandidate{}, invalidErr("invalid decision applicability level", "Use levels 3..6.")
				}
			}
			for _, role := range app.Roles {
				if !validID(api.ID(role)) {
					return api.DecisionCandidate{}, invalidErr("invalid decision applicability role", "Use valid role identifiers.")
				}
			}
			for _, id := range append(append([]api.ID(nil), app.ProjectIDs...), app.LifeIDs...) {
				if !validID(id) {
					return api.DecisionCandidate{}, invalidErr("invalid decision applicability ID", "Use valid project and life IDs.")
				}
			}
			cand := api.DecisionCandidate{
				ID:          rec.ID,
				Text:        doc.Text,
				EffectiveAt: doc.EffectiveAt,
				AppliesTo:   doc.AppliesTo,
				Binding:     doc.Binding,
			}
			return normalizeDecisionCandidate(cand, rec), nil
		}
		var cand api.DecisionCandidate
		if api.DecodeObject(raw, &cand) == nil && strings.TrimSpace(cand.Text) != "" {
			if cand.EffectiveAt != "" {
				if _, err := parseTimestamp(cand.EffectiveAt); err != nil {
					return api.DecisionCandidate{}, invalidErr("invalid decision effective_at timestamp", "Use RFC3339Nano UTC ending with Z.")
				}
			}
			return normalizeDecisionCandidate(cand, rec), nil
		}
		return api.DecisionCandidate{}, invalidErr("malformed structured decision JSON", "Encode structured decisions with schema laneboss.decision.v2.")
	}
	// Plain-text decision blobs remain nonbinding configuration-scoped canonical reminders per draft.4 §14.
	return normalizeDecisionCandidate(api.DecisionCandidate{
		ID:          rec.ID,
		Text:        trimmed,
		EffectiveAt: rec.RecordedAt,
		Binding:     false,
	}, rec), nil
}

func (s *Service) DashboardDecisions(ctx context.Context, scope api.Scope, request api.DashboardQuery) (api.DecisionView, error) {
	var empty api.DecisionView
	var err error
	scope, err = s.currentHumanScope(ctx, scope)
	if err != nil {
		return empty, err
	}
	if err := validateQuery(request); err != nil {
		return empty, err
	}
	offset, err := s.decodeCursor(scope, "dashboard.decisions", request, 0)
	if err != nil {
		return empty, err
	}

	decisionRecords, err := s.readAllRecords(ctx, scope, "decisions")
	if err != nil {
		return empty, wrapStoreErr(err, "decision store is unavailable")
	}

	byID := make(map[api.ID]api.DecisionCandidate)
	genByID := make(map[api.ID]api.Generation)
	supersededIDs := make(map[api.ID]bool)
	checkedDecisionStore := false

	applyDecisionRec := func(rec api.Record) error {
		if !isAuthoritativeDecisionRecord(rec) {
			return nil
		}
		for _, relID := range rec.RelatedIDs {
			if rec.Action == "supersede" && relID != "" {
				supersededIDs[relID] = true
				delete(byID, relID)
			}
		}
		checkedDecisionStore = true
		proj, err := s.deps.Store.Decision(ctx, scope, rec.ID)
		if err != nil {
			var typed *api.Error
			if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
				return integrityErr("decision projection is missing for canonical decision record", "Run laneboss store verify and preserve state evidence.")
			}
			return wrapStoreErr(err, "decision projection could not be read")
		}
		if proj.RecordID != rec.ID || proj.Candidate.ID != rec.ID || (proj.Status != "active" && proj.Status != "superseded" && proj.Status != "proposal") {
			return integrityErr("decision projection differs from its canonical record", "Run laneboss store verify and preserve state evidence.")
		}
		if proj.SupersedesID != "" {
			supersededIDs[proj.SupersedesID] = true
			delete(byID, proj.SupersedesID)
		}
		if proj.Status != "active" || rec.Action == "superseded" || supersededIDs[rec.ID] {
			supersededIDs[rec.ID] = true
			delete(byID, rec.ID)
			genByID[rec.ID] = rec.Generation
			return nil
		}
		decoded, err := s.decodeDecisionRecord(ctx, scope, rec)
		if err != nil {
			return err
		}
		cand := normalizeDecisionCandidate(proj.Candidate, rec)
		if !reflect.DeepEqual(cand, decoded) {
			return integrityErr("decision projection differs from its canonical record", "Verify the retained decision document and projection.")
		}
		if request.LifeID != "" && rec.LifeID != request.LifeID && rec.Actor.LifeID != request.LifeID ||
			request.Run != 0 && rec.Run != request.Run || request.Level != 0 && rec.Actor.Level != request.Level {
			return nil
		}
		if !matchesTimeBounds(cand.EffectiveAt, request) {
			return nil
		}
		if rec.Generation >= genByID[cand.ID] {
			byID[cand.ID] = cand
			genByID[cand.ID] = rec.Generation
		}
		return nil
	}

	for _, rec := range decisionRecords {
		if err := applyDecisionRec(rec); err != nil {
			return empty, err
		}
	}

	lanes, err := s.readAllLanes(ctx, scope, "")
	if err != nil {
		return empty, err
	}
	events, err := s.readLaneEvents(ctx, scope, lanes)
	if err != nil {
		return empty, err
	}
	for _, ev := range events {
		if ev.Origin != "service" || ev.Kind != "decision.changed" {
			continue
		}
		var rec api.Record
		if json.Unmarshal(ev.Payload, &rec) != nil {
			continue
		}
		if err := applyDecisionRec(rec); err != nil {
			return empty, err
		}
	}

	if !checkedDecisionStore {
		if _, err := s.deps.Store.Decision(ctx, scope, ""); err != nil {
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
				return empty, wrapStoreErr(err, "decision projection store is unavailable")
			}
		}
	}

	for id := range supersededIDs {
		delete(byID, id)
	}
	decisions := make([]api.DecisionCandidate, 0, len(byID))
	for _, d := range byID {
		decisions = append(decisions, d)
	}
	sort.Slice(decisions, func(i, j int) bool {
		ti, errI := parseTimestamp(decisions[i].EffectiveAt)
		tj, errJ := parseTimestamp(decisions[j].EffectiveAt)
		if errI == nil && errJ == nil && !ti.Equal(tj) {
			return ti.After(tj)
		}
		return decisions[i].ID < decisions[j].ID
	})

	if offset > len(decisions) {
		offset = len(decisions)
	}
	end := offset + request.Limit
	nextCursor := ""
	if end < len(decisions) {
		nextCursor = s.encodeCursor(scope, "dashboard.decisions", request, end, 0)
	} else {
		end = len(decisions)
	}
	page := decisions[offset:end]
	if page == nil {
		page = []api.DecisionCandidate{}
	}
	return api.DecisionView{
		Decisions: page,
		Cursor:    nextCursor,
	}, nil
}

func (s *Service) DashboardRefusals(ctx context.Context, scope api.Scope, request api.DashboardQuery) (api.RefusalView, error) {
	var empty api.RefusalView
	var err error
	scope, err = s.currentHumanScope(ctx, scope)
	if err != nil {
		return empty, err
	}
	if err := validateQuery(request); err != nil {
		return empty, err
	}
	offset, err := s.decodeCursor(scope, "dashboard.refusals", request, 0)
	if err != nil {
		return empty, err
	}
	rawLanes, err := s.readAllLanes(ctx, scope, "")
	if err != nil {
		return empty, err
	}
	// Resolve refusal metadata across every run before filtering.
	events, err := s.readLaneEvents(ctx, scope, rawLanes)
	if err != nil {
		return empty, err
	}
	// Require records inventory availability; never convert an unavailable store into an empty list.
	refusalRecords, err := s.readAllRecords(ctx, scope, "refusals")
	if err != nil {
		return empty, wrapStoreErr(err, "refusal records inventory is unavailable")
	}

	_, laneByID, _, _ := reconcileLanes(rawLanes, events)

	type countKey struct {
		ruleID api.ID
		level  int
	}
	countsByKey := make(map[countKey]*api.RefusalCount)
	getBucket := func(ruleID api.ID, level int) *api.RefusalCount {
		k := countKey{ruleID: ruleID, level: level}
		b, ok := countsByKey[k]
		if !ok {
			b = &api.RefusalCount{RuleID: ruleID, Level: level}
			countsByKey[k] = b
		}
		return b
	}

	unknownByLevel := make(map[int]bool)
	seenDecisions := make(map[api.ID]bool)
	var receipts []api.ID

	resolveLevel := func(lifeID api.ID, actorLevel int) int {
		if actorLevel >= 3 && actorLevel <= 6 {
			return actorLevel
		}
		if l, ok := laneByID[lifeID]; ok && l.Level >= 3 && l.Level <= 6 {
			return l.Level
		}
		return 3
	}

	lifeFilterOK := func(lifeID api.ID, level int) bool {
		if request.LifeID != "" && lifeID != request.LifeID {
			return false
		}
		if request.Level != 0 && level != request.Level {
			return false
		}
		if request.Driver != "" {
			l, ok := laneByID[lifeID]
			if !ok || l.Session.Driver != request.Driver {
				return false
			}
		}
		return true
	}

	applyDecision := func(pd api.PolicyDecision, lifeID api.ID, level int) {
		if pd.ID == "" || seenDecisions[pd.ID] {
			return
		}
		seenDecisions[pd.ID] = true
		recordedReceipt := false
		for _, rd := range pd.Rules {
			if rd.RuleID == "" {
				continue
			}
			b := getBucket(rd.RuleID, level)
			if !pd.AuditComplete {
				b.UnknownCoverage = true
			}
			switch rd.Result {
			case "critical_unscored":
				b.CriticalUnscored++
				recordedReceipt = true
			case "unscored":
				if rd.Critical {
					b.CriticalUnscored++
				} else {
					b.Unscored++
				}
				recordedReceipt = true
			case "refuse", "refused":
				if rd.Probability == nil {
					if rd.Critical {
						b.CriticalUnscored++
					} else {
						b.Unscored++
					}
				} else {
					b.Refused++
				}
				recordedReceipt = true
			case "warn", "warned":
				b.Warned++
				recordedReceipt = true
			}
		}
		if recordedReceipt || !pd.AuditComplete || pd.Result == "refuse" || pd.Result == "warn" || pd.Result == "unscored" {
			receipts = append(receipts, pd.ID)
		}
	}

	for _, ev := range events {
		if ev.Origin != "service" {
			continue
		}
		if request.Run != 0 && ev.Run != request.Run {
			continue
		}
		if !matchesTimeBounds(ev.RecordedAt, request) {
			continue
		}
		lvl := resolveLevel(ev.LifeID, ev.Actor.Level)
		if !lifeFilterOK(ev.LifeID, lvl) {
			continue
		}
		switch ev.Kind {
		case "policy.evaluated":
			var pd api.PolicyDecision
			if json.Unmarshal(ev.Payload, &pd) == nil {
				applyDecision(pd, ev.LifeID, lvl)
			}
		case "capture.gap", "capture.refused":
			unknownByLevel[lvl] = true
		case "capture.appended":
			var cr api.CaptureRecord
			if json.Unmarshal(ev.Payload, &cr) == nil && cr.Primary && cr.Coverage != "complete" {
				unknownByLevel[lvl] = true
			}
		case "lane.reviewed":
			var rr api.ReviewReceipt
			if json.Unmarshal(ev.Payload, &rr) == nil {
				if rr.Coverage != api.CoverageComplete || rr.Evidence == nil || rr.Evidence.Untrusted ||
					rr.Evidence.Coverage != api.CoverageComplete || rr.Evidence.Inventory.ToolCoverage != api.CoverageComplete {
					unknownByLevel[lvl] = true
				}
				if rr.Evidence != nil {
					// The existing dashboard table and CLI JSON display RuleID
					// beside coverage. Keep findings visible for partial and
					// untrusted results, independently of the coverage branch.
					for _, finding := range rr.Evidence.Findings {
						getBucket(api.ID(finding.Kind), lvl).Warned++
					}
				}
			}
		}
	}

	for _, rec := range refusalRecords {
		if request.Run != 0 && rec.Run != request.Run {
			continue
		}
		if rec.Origin != "service" {
			continue
		}
		if !matchesTimeBounds(rec.RecordedAt, request) {
			continue
		}
		lvl := resolveLevel(rec.LifeID, rec.Actor.Level)
		if !lifeFilterOK(rec.LifeID, lvl) {
			continue
		}
		raw, err := s.readVerifiedBlob(ctx, scope, rec.Content)
		if err != nil {
			return empty, err
		}
		var pd api.PolicyDecision
		if json.Unmarshal(raw, &pd) == nil && pd.ID != "" {
			applyDecision(pd, rec.LifeID, lvl)
		}
	}

	for lvl, unk := range unknownByLevel {
		if !unk {
			continue
		}
		foundForLevel := false
		for k, b := range countsByKey {
			if k.level == lvl {
				b.UnknownCoverage = true
				foundForLevel = true
			}
		}
		if !foundForLevel {
			b := getBucket("capture_coverage", lvl)
			b.UnknownCoverage = true
		}
	}

	counts := make([]api.RefusalCount, 0, len(countsByKey))
	for _, b := range countsByKey {
		counts = append(counts, *b)
	}
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].Level != counts[j].Level {
			return counts[i].Level < counts[j].Level
		}
		return counts[i].RuleID < counts[j].RuleID
	})

	if offset > len(counts) {
		offset = len(counts)
	}
	end := offset + request.Limit
	nextCursor := ""
	if end < len(counts) {
		nextCursor = s.encodeCursor(scope, "dashboard.refusals", request, end, 0)
	} else {
		end = len(counts)
	}
	page := counts[offset:end]
	if page == nil {
		page = []api.RefusalCount{}
	}
	if receipts == nil {
		receipts = []api.ID{}
	}
	return api.RefusalView{
		Counts:   page,
		Receipts: receipts,
		Cursor:   nextCursor,
	}, nil
}

func classifyResourceKind(path string) string {
	p := strings.TrimPrefix(path, "/")
	switch {
	case strings.HasPrefix(p, "plugins/"):
		return "plugin"
	case strings.HasPrefix(p, "scripts/"):
		return "script"
	case strings.HasPrefix(p, "tools/"):
		return "tool"
	case strings.HasPrefix(p, "templates/"):
		return "template"
	case strings.HasPrefix(p, "notes/"):
		return "note"
	default:
		return "config"
	}
}

func (s *Service) collectOrgResources(ctx context.Context, scope api.Scope, wantPlugins bool, request api.DashboardQuery) ([]api.Resource, api.Generation, error) {
	// Resolve org approval and worker history before display filters.
	lanes, err := s.readAllLanes(ctx, scope, "")
	if err != nil {
		return nil, 0, err
	}
	events, err := s.readLaneEvents(ctx, scope, lanes)
	if err != nil {
		return nil, 0, err
	}
	pol, polErr := s.deps.Store.Policy(ctx, scope)
	if polErr != nil {
		var typed *api.Error
		if !errors.As(polErr, &typed) || typed.Code != api.CodeNotFound {
			return nil, 0, wrapStoreErr(polErr, "policy inventory is unavailable")
		}
	}

	var maxGen api.Generation
	if polErr == nil && pol.Generation > maxGen {
		maxGen = pol.Generation
	}

	byPath := make(map[string]api.Resource)
	versions := make(map[string]api.Generation)
	observedVersions := make(map[string]api.Generation)
	simulatedPaths := make(map[string]bool)
	approvals := make(map[api.ID]api.ChangeApproval)
	for _, event := range events {
		if event.Origin != "service" {
			continue
		}
		var change api.ChangeEvent
		if (event.Kind == "org.change.approved" || event.Kind == "org.change.applied") && json.Unmarshal(event.Payload, &change) == nil && change.Approval != nil && change.Approval.ID != "" {
			approvals[change.Change.ID] = *change.Approval
		}
	}
	setResource := func(resource api.Resource, generation api.Generation, simulated bool) {
		current, exists := byPath[resource.Path]
		sameContent := exists && validDigest(current.SHA256) && current.SHA256 == resource.SHA256
		// A policy revision can advance without observing new bytes. Keep the
		// newest real observation of the same content, including older history.
		if sameContent {
			_, currentTimeErr := parseTimestamp(current.ObservedAt)
			if _, err := parseTimestamp(resource.ObservedAt); err == nil && (currentTimeErr != nil || generation >= observedVersions[resource.Path]) {
				current.ObservedAt, observedVersions[resource.Path] = resource.ObservedAt, generation
			}
		}
		if generation < versions[resource.Path] {
			if sameContent {
				if current.ApprovalID == "" {
					current.ApprovalID = resource.ApprovalID
				}
				byPath[resource.Path] = current
				simulatedPaths[resource.Path] = simulatedPaths[resource.Path] || simulated
			}
			return
		}
		if sameContent {
			resource.ObservedAt = current.ObservedAt
			if resource.ApprovalID == "" {
				resource.ApprovalID = current.ApprovalID
			}
			simulated = simulated || simulatedPaths[resource.Path]
		} else {
			delete(observedVersions, resource.Path)
			if _, err := parseTimestamp(resource.ObservedAt); err == nil {
				observedVersions[resource.Path] = generation
			}
		}
		versions[resource.Path], byPath[resource.Path], simulatedPaths[resource.Path] = generation, resource, simulated
	}
	verifiedPluginHashes := make(map[string]api.Digest)
	inventoryInitialized := polErr == nil && (pol.Generation > 0 || len(pol.Sources) > 0)

	if snap, err := s.deps.Store.OrgSnapshot(ctx, scope, api.OrgSnapshotRequest{OrgID: api.ID(scope.Config), Generation: maxGen}); err == nil {
		if snap.Ref.Generation > 0 || len(snap.Sources) > 0 || len(snap.Derived) > 0 {
			inventoryInitialized = true
		}
		if snap.Ref.Generation > maxGen {
			maxGen = snap.Ref.Generation
		}
		for _, rf := range append(snap.Sources, snap.Derived...) {
			if rf.Source.Path == "" {
				continue
			}
			k := rf.Kind
			if k == "" {
				k = classifyResourceKind(rf.Source.Path)
			}
			gen := rf.RevisionGeneration
			if gen == 0 {
				gen = rf.Source.Generation
			}
			if gen == 0 {
				gen = snap.Ref.Generation
			}
			setResource(api.Resource{
				ID:             rf.Source.ID,
				Kind:           k,
				Path:           rf.Source.Path,
				Version:        fmt.Sprintf("g%d", gen),
				SHA256:         rf.Content.SHA256,
				Source:         rf.Content,
				Declared:       true,
				VerifiedLoaded: false,
				ObservedAt:     snap.PublishedAt,
			}, gen, false)
		}
	} else {
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
			return nil, 0, wrapStoreErr(err, "org snapshot is unavailable")
		}
	}

	if polErr == nil {
		for _, src := range pol.Sources {
			if src.Path == "" {
				continue
			}
			k := classifyResourceKind(src.Path)
			gen := src.Generation
			if gen == 0 {
				gen = pol.Generation
			}
			if gen > maxGen {
				maxGen = gen
			}
			setResource(api.Resource{
				ID:             src.ID,
				Kind:           k,
				Path:           src.Path,
				Version:        fmt.Sprintf("g%d", gen),
				SHA256:         src.SHA256,
				Source:         api.BlobRef{ID: src.ID, SHA256: src.SHA256, Class: "policy"},
				Declared:       true,
				VerifiedLoaded: false,
			}, gen, false)
		}
	}

	for _, ev := range events {
		if ev.Origin != "service" {
			continue
		}
		switch ev.Kind {
		case "org.bootstrapped":
			var cv api.ConfigView
			if json.Unmarshal(ev.Payload, &cv) != nil {
				continue
			}
			inventoryInitialized = true
			if cv.Generation > maxGen {
				maxGen = cv.Generation
			}
			for _, src := range cv.Sources {
				if src.Path == "" {
					continue
				}
				k := classifyResourceKind(src.Path)
				gen := src.Generation
				if gen == 0 {
					gen = cv.Generation
				}
				setResource(api.Resource{
					ID:             src.ID,
					Kind:           k,
					Path:           src.Path,
					Version:        fmt.Sprintf("g%d", gen),
					SHA256:         src.SHA256,
					Source:         api.BlobRef{ID: src.ID, SHA256: src.SHA256, Class: "manifest"},
					Declared:       true,
					VerifiedLoaded: false,
					ObservedAt:     ev.RecordedAt,
				}, gen, false)
			}
			if cv.Projection.ID != "" {
				raw, err := s.readVerifiedBlob(ctx, scope, cv.Projection)
				if err != nil {
					return nil, 0, err
				}
				var rv struct {
					Resources []api.Resource `json:"resources"`
					Plugins   []api.Resource `json:"plugins"`
				}
				if json.Unmarshal(raw, &rv) == nil {
					for _, r := range append(rv.Resources, rv.Plugins...) {
						if r.Path == "" {
							r.Path = string(r.ID)
						}
						if r.Kind == "" {
							r.Kind = classifyResourceKind(r.Path)
						}
						if r.ObservedAt == "" {
							r.ObservedAt = ev.RecordedAt
						}
						if r.Kind == "plugin" {
							r.VerifiedLoaded = false
						}
						setResource(r, cv.Generation, false)
					}
				}
			}
		case "org.change.applied":
			var ce api.ChangeEvent
			if json.Unmarshal(ev.Payload, &ce) != nil || ce.Receipt == nil {
				continue
			}
			inventoryInitialized = true
			if ce.Receipt.NewGeneration > maxGen {
				maxGen = ce.Receipt.NewGeneration
			}
			approved := approvals[ce.Change.ID]
			if ce.Approval != nil {
				approved = *ce.Approval
			}
			approvalID := ce.Receipt.ApprovalID
			if approvalID == "" {
				approvalID = approved.ID
			}
			if approvalID == "" && ce.Approval != nil {
				approvalID = ce.Approval.ID
			}
			for _, delta := range append(ce.Change.Files, ce.Change.Derived...) {
				if delta.Action == "delete" {
					if ce.Receipt.NewGeneration >= versions[delta.Path] {
						delete(byPath, delta.Path)
						versions[delta.Path] = ce.Receipt.NewGeneration
						delete(simulatedPaths, delta.Path)
						delete(observedVersions, delta.Path)
					}
					continue
				}
				if delta.After == nil {
					continue
				}
				k := classifyResourceKind(delta.Path)
				resID := delta.After.ID
				if resID == "" {
					resID = api.ID(delta.Path)
				}
				setResource(api.Resource{
					ID:             resID,
					Kind:           k,
					Path:           delta.Path,
					Version:        fmt.Sprintf("g%d", ce.Receipt.NewGeneration),
					SHA256:         delta.After.SHA256,
					Source:         *delta.After,
					ApprovalID:     approvalID,
					Declared:       true,
					VerifiedLoaded: k != "plugin",
					ObservedAt:     ce.Receipt.AppliedAt,
				}, ce.Receipt.NewGeneration, ce.Receipt.SimulatedPresence || approved.SimulatedPresence)
			}
		case "data.materialized":
			if ev.Actor.Kind != "service" && ev.Actor.Kind != "worker" {
				continue
			}
			var mat api.Materialization
			if json.Unmarshal(ev.Payload, &mat) != nil {
				continue
			}
			for _, obj := range mat.Objects {
				p := strings.TrimPrefix(obj.SourceIdentity, "/")
				if p == "" {
					p = strings.TrimPrefix(obj.DestinationIdentity, "/")
				}
				if p != "" && validDigest(obj.SnapshotSHA256) {
					verifiedPluginHashes[p] = obj.SnapshotSHA256
				}
			}
			if mat.Manifest.ID != "" && mat.Manifest.Class == "manifest" {
				raw, err := s.readVerifiedBlob(ctx, scope, mat.Manifest)
				if err != nil {
					return nil, 0, err
				}
				var manifest api.ObjectManifest
				if json.Unmarshal(raw, &manifest) == nil && manifest.Schema == "laneboss.objects.v2" {
					for _, entry := range manifest.Entries {
						p := strings.TrimPrefix(entry.Path, "/")
						if p != "" && entry.Content != nil && entry.Content.Class != "capture" && entry.Content.Class != "transcript" && validDigest(entry.Content.SHA256) {
							verifiedPluginHashes[p] = entry.Content.SHA256
						}
					}
				}
			}
		}
	}

	if !inventoryInitialized {
		return nil, 0, unavailableErr("resource inventory is unavailable", "Initialize or verify the service configuration inventory before querying.")
	}

	var list []api.Resource
	for _, r := range byPath {
		if wantPlugins {
			if r.Kind != "plugin" {
				continue
			}
			loadedHash, ok := verifiedPluginHashes[strings.TrimPrefix(r.Path, "/")]
			r.VerifiedLoaded = ok && validDigest(r.SHA256) && validDigest(loadedHash) && loadedHash == r.SHA256
		} else {
			if r.Kind == "plugin" {
				continue
			}
		}
		if !matchesTimeBounds(r.ObservedAt, request) {
			continue
		}
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Path != list[j].Path {
			return list[i].Path < list[j].Path
		}
		return list[i].ID < list[j].ID
	})
	resourcePresencePaths(ctx, simulatedPaths)
	return list, maxGen, nil
}

func (s *Service) DashboardPlugins(ctx context.Context, scope api.Scope, request api.DashboardQuery) (api.ResourceView, error) {
	var empty api.ResourceView
	var err error
	scope, err = s.currentHumanScope(ctx, scope)
	if err != nil {
		return empty, err
	}
	if err := validateQuery(request); err != nil {
		return empty, err
	}
	list, gen, err := s.collectOrgResources(ctx, scope, true, request)
	if err != nil {
		return empty, err
	}
	offset, err := s.decodeCursor(scope, "dashboard.plugins", request, gen)
	if err != nil {
		return empty, err
	}
	if offset > len(list) {
		offset = len(list)
	}
	end := offset + request.Limit
	nextCursor := ""
	if end < len(list) {
		nextCursor = s.encodeCursor(scope, "dashboard.plugins", request, end, gen)
	} else {
		end = len(list)
	}
	page := list[offset:end]
	if page == nil {
		page = []api.Resource{}
	}
	resourcePagePresence(ctx, page)
	return api.ResourceView{
		Resources:  page,
		Generation: gen,
		Cursor:     nextCursor,
	}, nil
}

func (s *Service) DashboardResources(ctx context.Context, scope api.Scope, request api.DashboardQuery) (api.ResourceView, error) {
	var empty api.ResourceView
	var err error
	scope, err = s.currentHumanScope(ctx, scope)
	if err != nil {
		return empty, err
	}
	if err := validateQuery(request); err != nil {
		return empty, err
	}
	list, gen, err := s.collectOrgResources(ctx, scope, false, request)
	if err != nil {
		return empty, err
	}
	offset, err := s.decodeCursor(scope, "dashboard.resources", request, gen)
	if err != nil {
		return empty, err
	}
	if offset > len(list) {
		offset = len(list)
	}
	end := offset + request.Limit
	nextCursor := ""
	if end < len(list) {
		nextCursor = s.encodeCursor(scope, "dashboard.resources", request, end, gen)
	} else {
		end = len(list)
	}
	page := list[offset:end]
	if page == nil {
		page = []api.Resource{}
	}
	resourcePagePresence(ctx, page)
	return api.ResourceView{
		Resources:  page,
		Generation: gen,
		Cursor:     nextCursor,
	}, nil
}

func (s *Service) DashboardLifecycle(ctx context.Context, scope api.Scope, request api.DashboardQuery) (api.LanePage, error) {
	var empty api.LanePage
	var err error
	scope, err = s.currentHumanScope(ctx, scope)
	if err != nil {
		return empty, err
	}
	if err := validateQuery(request); err != nil {
		return empty, err
	}
	offset, err := s.decodeCursor(scope, "dashboard.lifecycle", request, 0)
	if err != nil {
		return empty, err
	}
	rawLanes, err := s.readAllLanes(ctx, scope, request.LifeID)
	if err != nil {
		return empty, err
	}
	// Reconcile current lane state across every run before filtering.
	events, err := s.readLaneEvents(ctx, scope, rawLanes)
	if err != nil {
		return empty, err
	}
	lanes, _, lastTime, _ := reconcileLanes(rawLanes, events)

	var matched []api.Lane
	for _, l := range lanes {
		if request.LifeID != "" && l.LifeID != request.LifeID {
			continue
		}
		if request.Run != 0 && l.Run != request.Run {
			continue
		}
		if request.Level != 0 && l.Level != request.Level {
			continue
		}
		if request.Driver != "" && l.Session.Driver != request.Driver {
			continue
		}
		if ts := lastTime[l.LifeID]; !matchesTimeBounds(ts, request) {
			continue
		}
		matched = append(matched, l)
	}

	if offset > len(matched) {
		offset = len(matched)
	}
	end := offset + request.Limit
	nextCursor := ""
	if end < len(matched) {
		nextCursor = s.encodeCursor(scope, "dashboard.lifecycle", request, end, 0)
	} else {
		end = len(matched)
	}
	page := matched[offset:end]
	if page == nil {
		page = []api.Lane{}
	}
	return api.LanePage{
		Lanes:  page,
		Cursor: nextCursor,
	}, nil
}

func (s *Service) DashboardApprovals(ctx context.Context, scope api.Scope, request api.DashboardQuery) (api.ApprovalView, error) {
	var empty api.ApprovalView
	var err error
	scope, err = s.currentHumanScope(ctx, scope)
	if err != nil {
		return empty, err
	}
	if err := validateQuery(request); err != nil {
		return empty, err
	}
	offset, err := s.decodeCursor(scope, "dashboard.approvals", request, 0)
	if err != nil {
		return empty, err
	}
	lanes, err := s.readAllLanes(ctx, scope, "")
	if err != nil {
		return empty, err
	}
	events, err := s.readLaneEvents(ctx, scope, lanes)
	if err != nil {
		return empty, err
	}

	changesByID := make(map[api.ID]api.ChangeRequest)
	var changeOrder []api.ID
	approvalsByID := make(map[api.ID]api.ChangeApproval)
	var approvalOrder []api.ID
	appsByID := make(map[api.ID]api.ChangeReceipt)
	var appOrder []api.ID

	for _, ev := range events {
		if ev.Origin != "service" {
			continue
		}
		switch ev.Kind {
		case "org.change.proposed", "org.change.approved", "org.change.applied", "org.change.rejected":
			var ce api.ChangeEvent
			if json.Unmarshal(ev.Payload, &ce) != nil || ce.Change.ID == "" {
				continue
			}
			if _, exists := changesByID[ce.Change.ID]; !exists {
				changeOrder = append(changeOrder, ce.Change.ID)
			}
			if ce.Change.Files == nil {
				ce.Change.Files = []api.ResourceDelta{}
			}
			if ce.Change.Derived == nil {
				ce.Change.Derived = []api.ResourceDelta{}
			}
			changesByID[ce.Change.ID] = ce.Change

			if ce.Approval != nil && ce.Approval.ID != "" {
				if _, exists := approvalsByID[ce.Approval.ID]; !exists {
					approvalOrder = append(approvalOrder, ce.Approval.ID)
				}
				approvalsByID[ce.Approval.ID] = *ce.Approval
			}
			if ce.Receipt != nil && ce.Receipt.ID != "" {
				if _, exists := appsByID[ce.Receipt.ID]; !exists {
					appOrder = append(appOrder, ce.Receipt.ID)
				}
				appsByID[ce.Receipt.ID] = *ce.Receipt
			}
		}
	}

	if len(changeOrder) == 0 {
		if _, err := s.deps.Store.Change(ctx, scope, ""); err != nil {
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
				return empty, wrapStoreErr(err, "change store is unavailable")
			}
		}
	}
	includedChanges := make(map[api.ID]bool)
	var changes []api.ChangeRequest
	for _, cid := range changeOrder {
		ch := changesByID[cid]
		updated, err := s.deps.Store.Change(ctx, scope, cid)
		if err != nil {
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
				return empty, wrapStoreErr(err, "change store is unavailable")
			}
		} else {
			if updated.ID != cid {
				return empty, integrityErr("change projection differs from its event", "Verify the pinned change inventory.")
			}
			if updated.Files == nil {
				updated.Files = []api.ResourceDelta{}
			}
			if updated.Derived == nil {
				updated.Derived = []api.ResourceDelta{}
			}
			ch = updated
		}
		if request.LifeID != "" && ch.Requester.LifeID != request.LifeID {
			continue
		}
		if request.Level != 0 && ch.Requester.Level != request.Level {
			continue
		}
		if !matchesTimeBounds(ch.CreatedAt, request) {
			continue
		}
		includedChanges[cid] = true
		changes = append(changes, ch)
	}

	if offset > len(changes) {
		offset = len(changes)
	}
	end := offset + request.Limit
	nextCursor := ""
	if end < len(changes) {
		nextCursor = s.encodeCursor(scope, "dashboard.approvals", request, end, 0)
	} else {
		end = len(changes)
	}
	pagedChanges := changes[offset:end]
	if pagedChanges == nil {
		pagedChanges = []api.ChangeRequest{}
	}

	pagedSet := make(map[api.ID]bool, len(pagedChanges))
	for _, ch := range pagedChanges {
		pagedSet[ch.ID] = true
	}

	var approvals []api.ChangeApproval
	for _, aid := range approvalOrder {
		ap := approvalsByID[aid]
		if includedChanges[ap.ChangeID] && pagedSet[ap.ChangeID] {
			approvals = append(approvals, ap)
		}
	}
	if approvals == nil {
		approvals = []api.ChangeApproval{}
	}

	var applications []api.ChangeReceipt
	for _, rid := range appOrder {
		rc := appsByID[rid]
		if includedChanges[rc.ChangeID] && pagedSet[rc.ChangeID] {
			applications = append(applications, rc)
		}
	}
	if applications == nil {
		applications = []api.ChangeReceipt{}
	}

	return api.ApprovalView{
		Changes:      pagedChanges,
		Approvals:    approvals,
		Applications: applications,
		Cursor:       nextCursor,
	}, nil
}
