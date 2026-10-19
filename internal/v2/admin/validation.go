package admin

import (
	"context"
	"errors"
	"os"
	"reflect"
	"regexp"

	"laneboss.io/laneboss/internal/v2/api"
)

const owner = "lb-v2-admin"

var (
	configPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	idPattern       = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	digestPattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	versionPattern  = regexp.MustCompile(`^[0-9][A-Za-z0-9._-]{0,31}$`)
	currencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)
)

func validConfig(value string) bool     { return configPattern.MatchString(value) }
func validID(value api.ID) bool         { return idPattern.MatchString(string(value)) }
func validDigest(value api.Digest) bool { return digestPattern.MatchString(string(value)) }

func failure(code api.ErrorCode, message string) *api.Error {
	return &api.Error{Code: code, Message: message, Owner: owner,
		Instead: "Retain the evidence; repair the installed administrator prerequisites before retrying the same operation."}
}

func contextError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return failure(api.CodeDeadline, "administrator operation deadline expired")
	}
	if ctx.Err() != nil {
		return failure(api.CodeCancelled, "administrator operation cancelled")
	}
	return nil
}

func validateAllocation(request api.HelperLeaseRequest, config string) error {
	if request.Backend == "darwin-seatbelt" {
		return &api.Error{Code: api.CodeUnsupported, Owner: "lb-v2-darwin", Message: "selected backend requires native Darwin", Instead: "Use the installed backend on its required operating system."}
	}
	if request.Config != config || !validConfig(config) || !validID(request.LifeID) ||
		!validID(request.RuntimeManifestID) || request.Backend != "linux-bwrap-landlock" {
		return failure(api.CodeInvalid, "invalid helper allocation identity or backend")
	}
	if err := validateCause(request.Cause, config, api.InternalHelperAllocate); err != nil {
		return err
	}
	if request.Cause.Target.LifeID != request.LifeID {
		return failure(api.CodeInvalid, "helper allocation cause targets a different life")
	}
	const maxExact = 1<<53 - 1
	b := request.Budget
	if b.WallMS <= 0 || b.WallMS > 604800000 || b.MemoryBytes < uint64(os.Getpagesize()) ||
		b.MemoryBytes > maxExact || b.Processes == 0 || b.Processes > 1048576 ||
		b.CPUSeconds > maxExact || b.DiskBytes == 0 || b.DiskBytes > maxExact || b.SpendMicros < 0 ||
		b.SpendMicros > maxExact {
		return failure(api.CodeInvalid, "invalid or unbounded helper resource budget")
	}
	if b.Currency != "" && !currencyPattern.MatchString(b.Currency) {
		return failure(api.CodeInvalid, "invalid helper budget currency")
	}
	return nil
}

func validatePreparation(request api.HelperLaunchRequest) error {
	if !validID(request.LeaseID) || !validID(request.PreparedSpecID) || !validDigest(request.SpecSHA256) {
		return failure(api.CodeInvalid, "invalid prepared helper request")
	}
	return validateCause(request.Cause, request.Cause.Config, api.InternalHelperPrepare)
}

func validateCause(cause api.InternalIntent, config string, kind api.InternalKind) error {
	if !validConfig(config) || cause.Config != config || cause.Kind != kind || !validID(cause.ID) ||
		!validID(cause.CauseOperationID) || !validID(cause.CauseRequestID) || !validID(cause.EffectID) ||
		!validID(cause.Target.LifeID) || cause.Target.Run == 0 || cause.Target.Run > 1<<53-1 ||
		cause.CancellationEpoch > 1<<53-1 || cause.LogicalTurnID != "" && !validID(cause.LogicalTurnID) {
		return failure(api.CodeInvalid, "invalid helper causal intent or target")
	}
	// This is an internal discriminant check, not a command restriction. Actual
	// provenance comes from the installed, lifetime-pinned service connection.
	if !validActor(cause.Actor) || !validActor(cause.RequestedBy) ||
		(cause.Actor.Kind != "service" && cause.Actor.Kind != "scheduler" &&
			cause.Actor.Kind != "watchdog" && cause.Actor.Kind != "worker") {
		return failure(api.CodeInvalid, "helper cause requires a service component and its original requester")
	}
	return nil
}

func validActor(actor api.Actor) bool {
	if !validID(actor.ID) || actor.LifeID != "" && !validID(actor.LifeID) || actor.Level < 0 || actor.Level > 6 {
		return false
	}
	switch actor.Kind {
	case "lane":
		return validID(actor.LifeID) && actor.Level >= 3 && actor.Level <= 6 && actor.Role != ""
	case "human", "service", "scheduler", "watchdog", "worker":
		return actor.LifeID == "" && actor.Level == 0 && actor.Role == ""
	default:
		return false
	}
}

func validateRelease(request api.HelperReleaseRequest, config string) error {
	if !validID(request.LeaseID) {
		return failure(api.CodeInvalid, "invalid helper lease identifier")
	}
	if err := validateCause(request.Cause, config, api.InternalHelperRelease); err != nil {
		return err
	}
	if request.Cause.Target != request.Observation.Handle.Target {
		return failure(api.CodeInvalid, "release cause and observation target differ")
	}
	return nil
}

// decodeStrict uses the shared exact field, null, duplicate, UTF-8 and
// surrogate rules. Private IPC does not get a weaker JSON dialect.
func decodeStrict(data []byte, target any) error {
	kind := api.JSONFrameObject
	switch target.(type) {
	case *helperRequest:
		kind = api.JSONFrameHelperRequest
	case *helperResponse, *credentialResponse:
		kind = api.JSONFrameHelperResponse
	case *isolationPacket, *probeResult:
		kind = api.JSONFrameHelperResult
	case *isolationProof:
		kind = api.JSONFrameIsolationProof
	case *isolationCanary:
		kind = api.JSONFrameIsolationCanary
	}
	return api.DecodeObjectFrame(data, target, kind)
}

// Private replies carry the administrator owner. Shared input validation
// retains the decoder's original error envelope for its public adapters.
func decodeReply(data []byte, target any) error {
	// A helper result may be a typed list or boolean (capture_drain_snapshot, capture_drain_ack,
	// containment_revoke); the object-root rule applies to object results only (box 83: lane release).
	if t := reflect.TypeOf(target); t != nil && t.Kind() == reflect.Pointer && t.Elem().Kind() != reflect.Struct && t.Elem().Kind() != reflect.Map {
		return ownInvalid(api.DecodeValueFrame(data, target, api.JSONFrameHelperResult), owner)
	}
	return ownInvalid(decodeStrict(data, target), owner)
}

// Attribution at the private IPC boundary preserves the original refusal.
// Joined failures and explicit upstream owners keep their existing meaning.
func ownInvalid(err error, component string) error {
	if typed, ok := err.(*api.Error); ok && typed != nil && typed.Code == api.CodeInvalid && typed.Owner == "" {
		owned := *typed
		owned.Owner = component
		return &owned
	}
	return err
}
