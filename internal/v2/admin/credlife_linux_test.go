//go:build linux

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type rotationNoticeFailure struct{}

func (rotationNoticeFailure) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

// The saved receipt is post-authentication component input. This checks the
// owner journal on completion replay, not broker authentication or containment.
func TestCredentialWithdrawalRotationNotice(t *testing.T) {
	for _, control := range []string{"rotation-required", "ordinary-release", "journal-failure"} {
		t.Run(control, func(t *testing.T) {
			id, err := randomID("rotation-notice-canary-")
			if err != nil {
				t.Fatal(err)
			}
			required := control != "ordinary-release"
			projection := api.CredentialProjectionRecord{State: "withdrawn",
				Authority:  api.CredentialProjectionAuthority{ID: api.ID(id)},
				Withdrawal: &api.CredentialWithdrawalReceipt{RotationRequired: required}}
			record := leaseRecord{Credentials: &credentialJournal{State: "withdrawn", Record: &projection}}
			var output bytes.Buffer
			var writer io.Writer = &output
			if control == "journal-failure" {
				writer = rotationNoticeFailure{}
			}
			ctx := context.WithValue(context.Background(), helperTimingKey{}, &helperRequestTrace{timing: writer})
			manager := &leaseManager{}
			err = manager.withdrawProjection(ctx, &record, api.InternalIntent{}, "release")
			if control == "journal-failure" {
				if !errors.Is(err, io.ErrClosedPipe) || !errors.Is(err, errHelperJournal) {
					t.Fatal("rotation-required journal failure was not reported", err)
				}
				if record.Credentials.Record != &projection || projection.State != "withdrawn" || !projection.Withdrawal.RotationRequired {
					t.Fatal("journal failure changed the durable rotation-required withdrawal")
				}
				return
			}
			if err != nil {
				t.Fatal("withdrawal replay failed", err)
			}
			if !required {
				if output.Len() != 0 {
					t.Fatal("ordinary release acquired a rotation-required notice")
				}
				return
			}
			var notice map[string]any
			if err := json.Unmarshal(output.Bytes(), &notice); err != nil || len(notice) != 3 ||
				notice["event"] != "credential_withdrawn" || notice["state"] != projection.State || notice["rotation_required"] != required {
				t.Fatal("owner journal lost the durable rotation-required withdrawal", err)
			}
			if bytes.Contains(output.Bytes(), []byte(id)) {
				t.Fatal("rotation-required notice exposed a private projection selector")
			}
		})
	}
}
