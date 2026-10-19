package messaging

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func resultJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestMailResultsStrict(t *testing.T) {
	f := newFixture(t)
	mail := f.send(t, "a3", "peer3")
	raw := resultJSON(t, mail)
	result, err := DecodeMailResult(raw)
	if err != nil || !reflect.DeepEqual(result, mail) {
		t.Fatalf("valid mail result changed: %v", err)
	}
	bad := []string{
		strings.Replace(string(raw), `"ask":false`, `"ask":false,"extra":true`, 1),
		strings.Replace(string(raw), `,"ask":false`, "", 1),
		strings.Replace(string(raw), `"ask":false`, `"ask":false,"ask":true`, 1),
		strings.Replace(string(raw), `"source":"cli"`, `"source":null`, 1),
		strings.Replace(string(raw), `"source":"cli"`, `"Source":"cli"`, 1),
		string(raw) + " {}", "null", "[]",
	}
	for i, body := range bad {
		if body == string(raw) {
			t.Fatalf("result red control %d did not change its input", i)
		}
		result, err := DecodeMailResult([]byte(body))
		wantCode(t, err, api.CodeIntegrity)
		if !reflect.DeepEqual(result, api.Mail{}) {
			t.Fatal("invalid result returned partially decoded mail")
		}
	}
}

func TestMailResultProvenance(t *testing.T) {
	for _, cell := range []string{"sender", "source", "sequence", "hash", "status", "destination"} {
		t.Run(cell, func(t *testing.T) {
			f := newFixture(t)
			mail := f.send(t, "a3", "peer3")
			switch cell {
			case "sender":
				mail.Sender.Kind = "service"
			case "source":
				mail.Source = "client-label"
			case "sequence":
				mail.QueuedSeq = 0
			case "hash":
				mail.Content.SHA256 = "wrong"
			case "status":
				mail.Status = "successful"
			case "destination":
				mail.ChannelGrantID = randomID(t)
			}
			_, err := DecodeMailResult(resultJSON(t, mail))
			wantCode(t, err, api.CodeIntegrity)
		})
	}
}

func TestMailboxResultBounds(t *testing.T) {
	f := newFixture(t)
	first, second := f.send(t, "a3", "peer3"), f.send(t, "peer3", "a3")
	page := api.MailPage{Messages: []api.Mail{first, second}, Cursor: ""}
	got, err := DecodeMailPageResult(resultJSON(t, page))
	if err != nil || !reflect.DeepEqual(got, page) {
		t.Fatalf("valid mailbox result changed: %v", err)
	}
	for _, cell := range []string{"duplicate", "order", "null", "oversize", "cursor"} {
		t.Run(cell, func(t *testing.T) {
			changed := api.MailPage{Messages: append([]api.Mail{}, page.Messages...), Cursor: page.Cursor}
			switch cell {
			case "duplicate":
				changed.Messages[1].ID = changed.Messages[0].ID
			case "order":
				changed.Messages[0], changed.Messages[1] = changed.Messages[1], changed.Messages[0]
			case "null":
				changed.Messages = nil
			case "oversize":
				changed.Messages = make([]api.Mail, 201)
			case "cursor":
				changed.Cursor = strings.Repeat("c", maxCursor+1)
			}
			got, err := DecodeMailPageResult(resultJSON(t, changed))
			wantCode(t, err, api.CodeIntegrity)
			if got.Messages != nil || got.Cursor != "" {
				t.Fatal("invalid mailbox result returned partial content")
			}
		})
	}
}

func TestBlobResultsStrict(t *testing.T) {
	f := newFixture(t)
	ref := f.blob(t, []byte("Exact uploaded bytes\n"))
	upload := api.BlobUpload{ObjectID: ref.ID, MaxChunkBytes: api.MaxChunkBytes, ExpiresAt: api.Timestamp(f.clock.now.Add(time.Hour).Format(time.RFC3339Nano))}
	got, err := DecodeMailUploadResult(resultJSON(t, upload))
	if err != nil || got != upload {
		t.Fatalf("valid upload result changed: %v", err)
	}
	blob, err := DecodeMailBlobResult(resultJSON(t, ref))
	if err != nil || blob != ref {
		t.Fatalf("valid blob result changed: %v", err)
	}
	for _, invalid := range []api.BlobUpload{
		{ObjectID: ref.ID, MaxChunkBytes: api.MaxChunkBytes + 1, ExpiresAt: upload.ExpiresAt},
		{ObjectID: ref.ID, MaxChunkBytes: 0, ExpiresAt: upload.ExpiresAt},
		{ObjectID: ref.ID, MaxChunkBytes: 1, ExpiresAt: "not-a-timestamp"},
		{ObjectID: ref.ID, MaxChunkBytes: 1, ExpiresAt: "2026-10-01T12:00:00+00:00"},
	} {
		_, err := DecodeMailUploadResult(resultJSON(t, invalid))
		wantCode(t, err, api.CodeIntegrity)
	}
	bad := ref
	bad.Class = "capture"
	_, err = DecodeMailBlobResult(resultJSON(t, bad))
	wantCode(t, err, api.CodeIntegrity)
	badJSON := bytes.Replace(resultJSON(t, ref), []byte(`"bytes":`), []byte(`"extra":true,"bytes":`), 1)
	_, err = DecodeMailBlobResult(badJSON)
	wantCode(t, err, api.CodeIntegrity)
}

func TestJSONUnicodeScalars(t *testing.T) {
	for _, cursor := range []string{`"\ud800"`, `"\udfff"`, `"\ud800\u0041"`} {
		_, err := DecodeMailList([]byte(`{"cursor":` + cursor + `,"limit":1}`))
		wantCode(t, err, api.CodeInvalid)
		_, err = DecodeMailPageResult([]byte(`{"messages":[],"cursor":` + cursor + `}`))
		wantCode(t, err, api.CodeIntegrity)
	}
	for _, cursor := range []string{`"\ud83d\ude80"`, `"\ufffd"`, `"\\ud800"`} {
		request, err := DecodeMailList([]byte(`{"cursor":` + cursor + `,"limit":1}`))
		if err != nil || request.Cursor == "" {
			t.Fatalf("valid Unicode cursor was rejected: %v", err)
		}
	}
}
