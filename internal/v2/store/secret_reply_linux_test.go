//go:build linux

package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets"
)

// Only the prior enrollment/session/assertion boundary is a component input.
// Each baseline allocation/import below comes from the real secrets owner,
// encrypted backend and SQLite transaction, before adversarial changes.
func committedStageReply(t *testing.T) (*metadataCase, api.Transaction, api.Operation, api.SecretStage) {
	t.Helper()
	ctx := context.Background()
	c := newMetadataCase(t)
	key, err := c.secrets.SecretKey(ctx, c.scope(t, "secret.key", api.Empty{}, false), api.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := secrets.SealStage(c.state.deps.Config, key, "reply.canary", "one", api.SecretMaterial{Bytes: []byte(testID(t))}, c.state.deps.Clock)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := api.WithReadAuthority(ctx, c.scope(t, "secret.stage", sealed, false))
	if err != nil {
		t.Fatal(err)
	}
	stage, err := c.secrets.SecretStage(ctx, scope, sealed)
	if err != nil {
		t.Fatal("real-store stage reply prerequisite failed", err)
	}
	input, operation := committedSecretReply(t, c, scope)
	if operation.FirstSeq != 0 || operation.LastSeq != 0 {
		t.Fatal("real-store stage invented a journal event for its metadata commit")
	}
	return c, input, operation, stage
}

func committedSecretReply(t *testing.T, c *metadataCase, scope api.Scope) (api.Transaction, api.Operation) {
	t.Helper()
	receipt, err := c.state.LookupReceipt(context.Background(), scope, requestKey(scope.Request))
	if err != nil || receipt.Reply == nil || receipt.Reply.Error != nil || receipt.Operation.Status != "succeeded" {
		t.Fatal("real secret mutation lost its successful receipt", err)
	}
	var first, last, head api.Sequence
	if err := c.state.db.QueryRowContext(context.Background(), `SELECT coalesce(min(seq),0),coalesce(max(seq),0),
 (SELECT coalesce(max(seq),0) FROM events) FROM events WHERE json_extract(data,'$.operation_id')=?`, string(receipt.Operation.ID)).Scan(&first, &last, &head); err != nil {
		t.Fatal(err)
	}
	persisted, err := c.state.Operation(context.Background(), scope, receipt.Operation.ID)
	if err != nil || receipt.FirstSeq != first || receipt.LastSeq != last || receipt.Operation.FirstSeq != first || receipt.Operation.LastSeq != last ||
		persisted.FirstSeq != first || persisted.LastSeq != last {
		t.Fatal("secret receipt range differs from its actual operation events", err)
	}
	if scope.Request.Method != "secret.stage" && (first == 0 || last < first) {
		t.Fatal("secret import or rotation lost its nonempty operation range")
	}
	view, err := c.state.BeginRead(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := view.Snapshot()
	if err := view.Close(); err != nil {
		t.Fatal(err)
	}
	health, err := c.state.HealthSnapshot(context.Background())
	if err != nil || head == 0 || snapshot.LastSeq != head || health.LastSeq != head {
		t.Fatal("operation range replaced the global read or health head", err)
	}
	return api.Transaction{Scope: scope, RawRequest: append([]byte(nil), receipt.RawRequest...),
		Reply: &api.RPCReply{Result: append([]byte(nil), receipt.Reply.Result...)}}, receipt.Operation
}

func checkSecretReply(t *testing.T, s *Service, input api.Transaction, operation api.Operation, failure, message string) {
	t.Helper()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			t.Error(err)
		}
	}()
	reply, err := s.finalReply(context.Background(), tx, input, operation)
	if message == "" {
		if err != nil || reply == nil || reply.Error != nil || !bytes.Equal(reply.Result, input.Reply.Result) {
			t.Fatal("valid committed secret reply failed correlation", err)
		}
		return
	}
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Owner != "lb-v2-service" || typed.Message != message || reply != nil {
		t.Fatalf("%s: %v", failure, err)
	}
}

type mismatchedStageWriter struct {
	*Service
	t         *testing.T
	allocated api.SecretStage
	commit    api.Commit
	err       error
}

func (s *mismatchedStageWriter) CommitSecretStage(ctx context.Context, input api.Transaction, allocated api.SecretStage) (api.Commit, error) {
	s.allocated = allocated
	expires, err := time.Parse(time.RFC3339Nano, string(allocated.ExpiresAt))
	if err != nil {
		return api.Commit{}, err
	}
	changed := allocated
	changed.ExpiresAt = api.Timestamp(expires.Add(-time.Millisecond).UTC().Format(time.RFC3339Nano))
	input.Reply = &api.RPCReply{Result: enrollmentJSON(s.t, changed)}
	s.commit, s.err = s.Service.CommitSecretStage(ctx, input, allocated)
	return s.commit, s.err
}

func TestSecretStageReplyProjection(t *testing.T) {
	for _, mode := range []string{"valid", "reply-expiry", "projection-id", "projection-name", "projection-version", "projection-expiry",
		"projection-config", "projection-owner", "projection-session", "projection-connection", "projection-request", "projection-request-id",
		"projection-operation", "projection-key", "missing-projection"} {
		t.Run(mode, func(t *testing.T) {
			c, input, operation, stage := committedStageReply(t)
			ctx := context.Background()
			var record secretStageRecord
			if err := storedProjection(ctx, c.state.db, "secret_stage", stage.ID, &record); err != nil {
				t.Fatal("real stage has no stored allocation", err)
			}
			message := "secret stage reply differs from its committed allocation"
			switch mode {
			case "valid":
				message = ""
			case "reply-expiry":
				stage.ExpiresAt = api.Timestamp(c.state.deps.Clock.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano))
				input.Reply.Result = enrollmentJSON(t, stage)
			case "projection-id":
				record.Stage.ID = testID(t)
			case "projection-name":
				record.Stage.Name += ".foreign"
			case "projection-version":
				record.Stage.Version = "foreign"
			case "projection-expiry":
				record.Stage.ExpiresAt = api.Timestamp(c.state.deps.Clock.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano))
			case "projection-config":
				record.Config = "foreign"
			case "projection-owner":
				record.Owner.ID = testID(t)
			case "projection-session":
				record.Authority.SessionID = testID(t)
			case "projection-connection":
				record.Authority.ConnectionID = testID(t)
			case "projection-request":
				record.Request.IdempotencyKey = testID(t)
			case "projection-request-id":
				record.RequestID = testID(t)
			case "projection-operation":
				record.OperationID = testID(t)
			case "projection-key":
				record.KeyID = testID(t)
			case "missing-projection":
				if _, err := c.state.db.ExecContext(ctx, "DELETE FROM projections WHERE kind='secret_stage' AND id=?", string(stage.ID)); err != nil {
					t.Fatal(err)
				}
				message = "secret stage reply has no committed allocation"
			}
			if mode != "valid" && mode != "reply-expiry" && mode != "missing-projection" {
				// Change only the persisted allocation; the request, reply and
				// operation remain the original real successful mutation.
				fixtureProjection(t, c.state, "secret_stage", stage.ID, 2, record)
			}
			checkSecretReply(t, c.state, input, operation, "secret stage projection mismatch escaped correlation", message)
		})
	}
	t.Run("publication-rollback", func(t *testing.T) {
		c := newMetadataCase(t)
		ctx := context.Background()
		writer := &mismatchedStageWriter{Service: c.state, t: t}
		owner, err := secrets.New(secrets.Dependencies{Config: c.state.deps.Config, Store: writer, Backend: c.backend,
			Human: c.identities, ProjectionIdentity: c.identities, Clock: c.state.deps.Clock})
		if err != nil {
			t.Fatal(err)
		}
		key, err := owner.SecretKey(ctx, c.scope(t, "secret.key", api.Empty{}, false), api.Empty{})
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := secrets.SealStage(c.state.deps.Config, key, "reply.canary", "one", api.SecretMaterial{Bytes: []byte(testID(t))}, c.state.deps.Clock)
		if err != nil {
			t.Fatal(err)
		}
		scope := c.scope(t, "secret.stage", sealed, false)
		reply, err := owner.SecretStage(ctx, scope, sealed)
		var typed *api.Error
		if !errors.As(writer.err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != "secret stage reply differs from its committed allocation" ||
			err != writer.err || reply != (api.SecretStage{}) || writer.commit.Reply != nil || writer.allocated.ID == "" {
			t.Fatalf("secret stage projection mismatch escaped correlation: publication accepted a reply outside its allocation: %v", err)
		}
		var record secretStageRecord
		expectCode(t, storedProjection(ctx, c.state.db, "secret_stage", writer.allocated.ID, &record), api.CodeNotFound)
		_, err = c.state.LookupReceipt(ctx, scope, requestKey(scope.Request))
		expectCode(t, err, api.CodeNotFound)
	})
}

func TestSecretInfoReplyProjection(t *testing.T) {
	for _, method := range []api.Method{"secret.import", "secret.rotate"} {
		t.Run(string(method), func(t *testing.T) {
			for _, mode := range []string{"valid", "reply-version", "source-projection", "head-projection", "operation", "missing-source", "missing-head"} {
				t.Run(mode, func(t *testing.T) {
					c := newMetadataCase(t)
					ctx := context.Background()
					var scope api.Scope
					var info api.SecretInfo
					var err error
					if method == "secret.import" {
						stage := c.stageSecret(t, "reply.canary", "one", []byte(testID(t)))
						request := api.SecretImportRequest{Name: stage.Name, Version: stage.Version, SealedUploadID: stage.ID}
						scope = c.scope(t, method, request, true)
						info, err = c.secrets.SecretImport(ctx, scope, request)
					} else {
						prior := c.importSecret(t, "reply.canary", []byte(testID(t)))
						stage := c.stageSecret(t, prior.Name, "two", []byte(testID(t)))
						request := api.SecretRotateRequest{Name: prior.Name, ExpectedVersion: prior.Version, SealedUploadID: stage.ID}
						scope = c.scope(t, method, request, true)
						info, err = c.secrets.SecretRotate(ctx, scope, request)
					}
					if err != nil {
						t.Fatal("real-store secret reply prerequisite failed", err)
					}
					input, operation := committedSecretReply(t, c, scope)
					message := "secret reply differs from its committed source metadata"
					switch mode {
					case "valid":
						message = ""
					case "reply-version":
						info.Version = "foreign"
						input.Reply.Result = enrollmentJSON(t, info)
					case "source-projection", "head-projection":
						kind, id := "secret_source", info.SourceHandle
						if mode == "head-projection" {
							kind, id = "secret_head", secretNameID(info.Name)
						}
						var record secretMetadata
						if err := storedProjection(ctx, c.state.db, kind, id, &record); err != nil {
							t.Fatal(err)
						}
						record.Info.KeyID = testID(t)
						fixtureProjection(t, c.state, kind, id, record.Generation+1, record)
					case "operation":
						operation.ID = testID(t)
					case "missing-source", "missing-head":
						kind, id := "secret_source", info.SourceHandle
						if mode == "missing-head" {
							kind, id = "secret_head", secretNameID(info.Name)
						}
						if _, err := c.state.db.ExecContext(ctx, "DELETE FROM projections WHERE kind=? AND id=?", kind, string(id)); err != nil {
							t.Fatal(err)
						}
						message = "secret reply has no committed source metadata"
					}
					checkSecretReply(t, c.state, input, operation, "secret source projection mismatch escaped correlation", message)
				})
			}
		})
	}
}
