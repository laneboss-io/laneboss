package templates

import (
	"context"
	"slices"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/objectread"
)

func checkScope(scope api.Scope) error {
	if !safeID.MatchString(scope.Config) || !safeID.MatchString(string(scope.Actor.ID)) {
		return problem(api.CodeUnauthenticated, "briefing requires an authenticated configuration scope",
			"Use the installed service binding without changing a live session's configuration.")
	}
	if scope.Request.Config != "" && scope.Request.Config != scope.Config {
		return problem(api.CodeForbidden, "briefing configuration differs from its authenticated binding",
			"Use the configuration bound to this endpoint.")
	}
	if scope.Actor.Kind != "lane" && scope.Actor.Kind != "worker" && scope.Actor.Kind != "human" && scope.Actor.Kind != "service" {
		return problem(api.CodeForbidden, "this principal cannot render a briefing",
			"Use an authenticated lane or human endpoint.")
	}
	return nil
}

func lifeBound(scope api.Scope) bool {
	return scope.Actor.Kind == "lane" || scope.Actor.Kind == "worker"
}

// Resolve the authenticated life first. Life/grant IDs are claims to compare,
// never selectors for a different life or grant set, even on an internal call.
func (s *Service) selfLane(ctx context.Context, scope api.Scope, role api.RoleContext, grantID, lifeID api.ID) (*api.Lane, error) {
	if !lifeBound(scope) {
		return nil, nil
	}
	if !safeID.MatchString(string(scope.Actor.LifeID)) || lifeID != "" && lifeID != scope.Actor.LifeID {
		return nil, problem(api.CodeForbidden, "briefing life claim differs from the authenticated life",
			"Use this endpoint's own life; request labels cannot select another principal.")
	}
	lane, err := s.deps.Store.Lane(ctx, scope, api.LifeRef{LifeID: scope.Actor.LifeID})
	if err != nil {
		return nil, err
	}
	if lane.LifeID != scope.Actor.LifeID || !safeID.MatchString(string(lane.GrantSetID)) {
		return nil, integrity("authenticated briefing life has an inconsistent projection")
	}
	if lane.Level != role.Level || lane.Role != role.Role || grantID != "" && grantID != lane.GrantSetID {
		return nil, problem(api.CodeForbidden, "briefing role or grant claim differs from the authenticated life",
			"Use the current role and grant set of this endpoint's own life.")
	}
	return &lane, nil
}

func selfContext(scope api.Scope, requested api.RoleContext) error {
	if scope.Actor.Kind == "lane" &&
		(!safeID.MatchString(string(scope.Actor.LifeID)) || scope.Actor.Level != requested.Level || scope.Actor.Role != requested.Role) {
		return problem(api.CodeForbidden, "requested briefing context differs from the authenticated lane",
			"Use this lane's recorded level and role; only the lifecycle service renders a new child.")
	}
	return nil
}

func checkTaskRef(ref api.BlobRef) error {
	if ref.Class != "task" {
		return invalid("assigned task must reference a committed task object")
	}
	return checkBlobRef(ref)
}

func checkBlobRef(ref api.BlobRef) error {
	if !safeID.MatchString(string(ref.ID)) || !safeDigest.MatchString(string(ref.SHA256)) || ref.Bytes <= 0 || ref.Bytes > api.MaxObjectBytes {
		return invalid("invalid committed blob reference")
	}
	switch ref.Class {
	case "task", "prompt", "report", "artifact", "capture", "transcript", "policy", "manifest",
		"judge_request", "judge_raw", "archive", "record":
	default:
		return invalid("unknown committed blob class")
	}
	return nil
}

func (s *Service) readBlob(ctx context.Context, scope api.Scope, ref api.BlobRef) (resultBytes []byte, resultErr error) {
	if err := checkBlobRef(ref); err != nil {
		return nil, err
	}
	scope, release, err := objectread.Bind(ctx, s.deps.Store, scope)
	if err != nil {
		return nil, err
	}
	defer release(&resultErr)
	metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		return nil, err
	}
	if metadata.Ref != ref || metadata.ACL.Config != scope.Config || metadata.ACL.Generation == 0 ||
		metadata.Origin == "" || metadata.CommittedAt == "" {
		return nil, integrity("blob claim differs from its committed metadata or configuration")
	}
	return ReadVerifiedBlob(ctx, ref, func(ctx context.Context, request api.BlobReadRequest) (api.BlobChunk, error) {
		return s.deps.Store.Blob(ctx, scope, request)
	})
}

// GroupLanes is a pure view over already-authorized projections. It does not
// infer visibility from levels, query another subtree, or hide unknown states.
func GroupLanes(lanes []api.Lane) (api.LaneGroups, error) {
	groups := api.LaneGroups{
		Running: []api.ID{}, Ended: []api.ID{}, Accepted: []api.ID{},
		Lost: []api.ID{}, Idle: []api.ID{}, Others: []api.ID{},
	}
	seen := map[api.ID]bool{}
	for _, lane := range lanes {
		if !safeID.MatchString(string(lane.LifeID)) || seen[lane.LifeID] {
			return api.LaneGroups{}, integrity("lane briefing view has invalid or duplicate life identifiers")
		}
		seen[lane.LifeID] = true
		if lane.Cleaned {
			groups.Others = append(groups.Others, lane.LifeID)
			continue
		}
		switch lane.State {
		case "preparing", "running", "stopping", "profile_wait":
			groups.Running = append(groups.Running, lane.LifeID)
		case "verifying":
			groups.Ended = append(groups.Ended, lane.LifeID)
		case "accepted", "merged":
			groups.Accepted = append(groups.Accepted, lane.LifeID)
		case "lost":
			groups.Lost = append(groups.Lost, lane.LifeID)
		case "idle":
			groups.Idle = append(groups.Idle, lane.LifeID)
		case "abandoned":
			groups.Others = append(groups.Others, lane.LifeID)
		default:
			return api.LaneGroups{}, integrity("lane briefing view contains an unknown lifecycle state")
		}
	}
	for _, group := range [][]api.ID{groups.Running, groups.Ended, groups.Accepted, groups.Lost, groups.Idle, groups.Others} {
		slices.SortFunc(group, func(a, b api.ID) int { return strings.Compare(string(a), string(b)) })
	}
	return groups, nil
}
