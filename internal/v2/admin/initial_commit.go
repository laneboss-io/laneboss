package admin

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/objectread"
)

// InitialCommitter is an installed service/store capability, never a public
// RPC. Its implementation checks VerifyInitialTransaction before Transact.
type InitialCommitter interface {
	CommitInitial(context.Context, api.Transaction) (api.Commit, error)
}

func PublishInitial(ctx context.Context, request InitialRequest, store api.StateStore, clock api.Clock, enrollment ...InitialProfileEnrollment) (InitialReceipt, error) {
	channel, ok := ctx.Value(enrollmentChannelKey{}).(*enrollmentChannel)
	if !ok || channel == nil {
		return InitialReceipt{}, failure(api.CodeForbidden, "initial import requires the installed administrator channel")
	}
	if err := CheckEnrollmentChannel(ctx, channel.endpoint); err != nil {
		return InitialReceipt{}, err
	}
	if channel.initialRequest == nil || *channel.initialRequest != request {
		return InitialReceipt{}, failure(api.CodeForbidden, "initial publication differs from its credential-verified frame")
	}
	if nilEnrollmentPort(store) || nilEnrollmentPort(clock) {
		return InitialReceipt{}, api.NotImplemented("lb-v2-service", "initial publication store and clock")
	}
	bundle, err := initialStage(ctx, "load_validate", func() (initialBundle, error) {
		return loadInitialInstalled(ctx, channel.endpoint, request)
	})
	if err != nil {
		return InitialReceipt{}, err
	}
	if len(enrollment) > 1 {
		return InitialReceipt{}, failure(api.CodeInvalid, "initial profile enrollment binding repeats")
	}
	if len(enrollment) == 1 {
		bundle.enrollment = enrollment[0]
	}
	return commitInitial(ctx, bundle, store, clock, channel)
}

func commitInitial(ctx context.Context, b initialBundle, store api.StateStore, clock api.Clock, channel *enrollmentChannel) (InitialReceipt, error) {
	if err := CheckEnrollmentChannel(ctx, channel.endpoint); err != nil {
		return InitialReceipt{}, err
	}
	validated, err := initialStage(ctx, "revalidate", func() (initialBundle, error) {
		return validateInitialObserved(ctx, b.ref, b.raw, b.objects, b.manifest.Config)
	})
	if err != nil {
		return InitialReceipt{}, err
	}
	validated.enrollment = b.enrollment
	b = validated
	actor := api.Actor{Kind: "service", ID: api.ID("initial-" + b.manifest.Config)}
	scope := api.Scope{Config: b.manifest.Config, Actor: actor, Source: "service", PolicyGeneration: 1}
	metadata, err := store.ObjectMetadata(ctx, scope, initialReceiptID(scope.Config))
	if err == nil {
		return readInitial(ctx, b, store, scope, metadata, channel)
	}
	var typed *api.Error
	if err != nil && (!errors.As(err, &typed) || typed.Code != api.CodeNotFound) {
		return InitialReceipt{}, err
	}
	writer, ok := store.(InitialCommitter)
	if !ok {
		return InitialReceipt{}, api.NotImplemented("lb-v2-service", "protected initial publication commit")
	}
	if err := manifest.Root(b.profiles, clock.Now()); err != nil {
		return InitialReceipt{}, err
	}
	tx, err := initialStage(ctx, "plan", func() (api.Transaction, error) {
		now := api.Timestamp(clock.Now().UTC().Format(time.RFC3339Nano))
		_, writes, err := initialProfilePlan(ctx, b, now)
		if err != nil {
			return api.Transaction{}, err
		}
		b.profileWrites = writes
		return initialPlan(b, actor, now)
	})
	if err != nil {
		return InitialReceipt{}, err
	}
	_, err = initialStage(ctx, "seal", func() (struct{}, error) {
		channel.initial = &tx
		sealed, err := json.Marshal(tx)
		if err != nil {
			return struct{}{}, err
		}
		channel.initialHash = digestBytes(sealed)
		return struct{}{}, VerifyInitialTransaction(ctx, tx)
	})
	if err != nil {
		return InitialReceipt{}, err
	}
	commit, err := initialStage(ctx, "commit", func() (api.Commit, error) {
		return writer.CommitInitial(ctx, tx)
	})
	if err != nil {
		var timingFailure *initialTimingFailure
		if errors.As(err, &timingFailure) {
			return InitialReceipt{}, err
		}
		if errors.As(err, &typed) && (typed.Code == api.CodeConflict || typed.Code == api.CodeIdempotencyConflict) {
			retained, readErr := store.ObjectMetadata(ctx, scope, initialReceiptID(scope.Config))
			if readErr == nil {
				return readInitial(ctx, b, store, scope, retained, channel)
			}
		}
		return InitialReceipt{}, err
	}
	if commit.Operation.ID != tx.Internal.CauseOperationID || commit.Operation.Status != "succeeded" || commit.Operation.Error != nil || commit.FirstSeq == 0 || commit.LastSeq < commit.FirstSeq {
		return InitialReceipt{}, initialFailure("commit")
	}
	metadata, err = store.ObjectMetadata(ctx, scope, initialReceiptID(scope.Config))
	if err != nil {
		return InitialReceipt{}, err
	}
	return readInitial(ctx, b, store, scope, metadata, channel)
}

func initialRead(ctx context.Context, store api.StateStore, scope api.Scope, ref api.BlobRef) ([]byte, error) {
	return initialStage(ctx, "read_object", func() ([]byte, error) {
		return initialReadObject(ctx, store, scope, ref)
	})
}

func initialReadObject(ctx context.Context, store api.StateStore, scope api.Scope, ref api.BlobRef) (result []byte, resultErr error) {
	if !initialRef(ref) {
		return nil, initialFailure("object pin")
	}
	return initialReadBytes(ctx, store, scope, ref)
}

// The caller validates the closed class and exact metadata before this reader.
// Profile evidence is generated by the installed producer, never imported as
// an extra object in the administrator's input inventory.
func initialReadBytes(ctx context.Context, store api.StateStore, scope api.Scope, ref api.BlobRef) (result []byte, resultErr error) {
	scope, release, err := objectread.Bind(ctx, store, scope)
	if err != nil {
		return nil, err
	}
	defer release(&resultErr)
	data := make([]byte, 0, int(ref.Bytes))
	for int64(len(data)) < ref.Bytes {
		part, err := store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: int64(len(data)), Limit: int(min(int64(api.MaxChunkBytes), ref.Bytes-int64(len(data))))})
		if err != nil {
			return nil, err
		}
		if part.ObjectID != ref.ID || part.Offset != int64(len(data)) || len(part.Data) == 0 || int64(len(part.Data)) > ref.Bytes-int64(len(data)) || digestBytes(part.Data) != part.SHA256 {
			return nil, initialFailure("object range")
		}
		data = append(data, part.Data...)
	}
	if digestBytes(data) != ref.SHA256 {
		return nil, initialFailure("object bytes")
	}
	return data, nil
}

func readInitial(ctx context.Context, b initialBundle, store api.StateStore, scope api.Scope, marker api.ObjectMetadata, channel *enrollmentChannel) (InitialReceipt, error) {
	return initialStage(ctx, "read_back", func() (InitialReceipt, error) {
		return readInitialState(ctx, b, store, scope, marker, channel)
	})
}

func readInitialState(ctx context.Context, b initialBundle, store api.StateStore, scope api.Scope, marker api.ObjectMetadata, channel *enrollmentChannel) (result InitialReceipt, resultErr error) {
	var empty InitialReceipt
	scope, release, err := objectread.Bind(ctx, store, scope)
	if err != nil {
		return empty, err
	}
	defer release(&resultErr)
	actualMarker, err := store.ObjectMetadata(ctx, scope, marker.Ref.ID)
	if err != nil {
		return empty, err
	}
	if !reflect.DeepEqual(actualMarker, marker) {
		return empty, initialFailure("receipt metadata")
	}
	if marker.Ref.ID != initialReceiptID(scope.Config) || marker.Ref.Class != "manifest" || marker.ACL.Config != scope.Config || marker.Origin != "service" || marker.SourceOperationID == "" || marker.CommittedAt == "" {
		return empty, initialFailure("receipt metadata")
	}
	raw, err := initialRead(ctx, store, scope, marker.Ref)
	if err != nil {
		return empty, err
	}
	if err := initialMarkerMatches(raw, b); err != nil {
		return empty, err
	}
	op, err := store.Operation(ctx, scope, marker.SourceOperationID)
	if err != nil {
		return empty, err
	}
	if op.ID != api.ID("initial-op-"+string(b.manifest.ID)) || op.Status != "succeeded" || op.Error != nil || op.FirstSeq == 0 || op.LastSeq != op.FirstSeq {
		return empty, initialFailure("receipt operation")
	}
	page, err := store.Events(ctx, scope, api.EventTailRequest{Since: op.FirstSeq - 1})
	if err != nil {
		return empty, err
	}
	if len(page.Events) == 0 {
		return empty, initialFailure("receipt event")
	}
	event := page.Events[0]
	if event.Kind != "org.bootstrapped" || event.OperationID != op.ID || event.Config != scope.Config || event.Seq != op.FirstSeq || event.ID != api.ID("initial-event-"+string(b.manifest.ID)) || !reflect.DeepEqual([]byte(event.Payload), raw) {
		return empty, initialFailure("receipt event binding")
	}
	snapshot, err := store.OrgSnapshot(ctx, scope, api.OrgSnapshotRequest{OrgID: api.ID(scope.Config), Generation: 1})
	if err != nil {
		return empty, err
	}
	want := b.sources
	want.PublishedBy = snapshot.PublishedBy
	want.PublishedAt = snapshot.PublishedAt
	if snapshot.PublishedBy != b.manifest.ID || snapshot.PublishedAt == "" || !reflect.DeepEqual(snapshot, want) {
		return empty, initialFailure("org snapshot")
	}
	actual, err := store.Policy(ctx, scope)
	if err != nil {
		return empty, err
	}
	if !reflect.DeepEqual(actual, b.policy) {
		return empty, initialFailure("policy")
	}
	refs := append([]api.BlobRef{b.ref}, b.manifest.Objects...)
	for _, ref := range refs {
		m, err := store.ObjectMetadata(ctx, scope, ref.ID)
		if err != nil {
			return empty, err
		}
		if m.Ref != ref || m.ACL.Config != scope.Config || m.Origin != "service" || m.SourceOperationID != op.ID {
			return empty, initialFailure("published object metadata")
		}
		if _, err := initialRead(ctx, store, scope, ref); err != nil {
			return empty, err
		}
	}
	if err := installInitialProfiles(ctx, b, store, scope, op.ID, snapshot.PublishedAt, channel); err != nil {
		return empty, err
	}
	if err := CheckEnrollmentChannel(ctx, channel.endpoint); err != nil {
		return empty, err
	}
	receipt := InitialReceipt{Schema: "laneboss.initial-receipt.v2", Config: scope.Config, ID: b.manifest.ID, Manifest: b.ref, Receipt: marker.Ref, OperationID: op.ID, EventID: event.ID, CommittedSeq: event.Seq, Generation: 1}
	channel.initialReceipt = &receipt
	return receipt, nil
}
