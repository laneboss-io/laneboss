//go:build linux

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestHelperNativeRequestJournal(t *testing.T) {
	for _, mode := range []string{"refused", "closed"} {
		t.Run(mode, func(t *testing.T) {
			server, client := nativePair(t)
			if mode == "closed" {
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
			}
			var journal bytes.Buffer
			err := serveHelperConnectionWithJournal(context.Background(), server, testBinding(), nil, &journal)
			if err == nil || bytes.Count(journal.Bytes(), []byte{'\n'}) != 1 {
				t.Fatal("native helper refusal was swallowed or not journaled exactly once", err)
			}
			var entry map[string]string
			if json.Unmarshal(journal.Bytes(), &entry) != nil || len(entry) != 4 || entry["event"] != "helper_request" || entry["method"] != "unknown" || !api.ValidHelperReason(entry["reason"]) {
				t.Fatal("native pre-authentication refusal lost its closed diagnostic shape")
			}
			if mode == "closed" {
				if entry["reason"] != "reply_transport" {
					t.Fatal("native closed request lost the failed reply check")
				}
				return
			}
			var response helperResponse
			if err := readFrameForJournal(client, &response); err != nil {
				t.Fatal(err)
			}
			var typed *api.Error
			if !errors.As(err, &typed) || response.Error == nil || response.Error.Code != typed.Code || entry["code"] != string(typed.Code) || response.Reason != entry["reason"] {
				t.Fatal("native helper reply and journal lost their actual typed refusal or check")
			}
		})
	}
}
