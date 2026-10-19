package messaging

import (
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestContentScreen(t *testing.T) {
	good := [][]byte{
		[]byte("Original text\r\nwith tabs\tand 中文.\n"),
		[]byte("API_KEY=${SELECTED_KEY}\n"),
		[]byte("secret: <granted name>\n"),
		[]byte("Run a newly built executable in the work area.\n"),
		[]byte("<script>inert message text</script>\n"),
	}
	for i, data := range good {
		copy := append([]byte{}, data...)
		if err := CheckContent(data); err != nil || !reflect.DeepEqual(copy, data) {
			t.Fatalf("valid content cell %d changed or failed: %v", i, err)
		}
	}
	bad := [][]byte{
		{}, []byte(" \n\t"), {0xff}, []byte("unsafe\x1b[31m"), []byte("a\x00b"),
		[]byte(strings.Repeat("m", MaxMailBytes+1)),
		[]byte("bearer " + strings.Repeat("a1", 12)),
		[]byte("api_key = \"disposable-literal\""),
		[]byte("Authorization: Basic " + strings.Repeat("Y", 12)),
		[]byte("<!-- laneboss launcher block: begin -->"),
	}
	for i, data := range bad {
		err := CheckContent(data)
		wantCode(t, err, api.CodeInvalid)
		if len(data) > 10 && strings.Contains(err.Error(), string(data)) {
			t.Fatalf("screen exposed rejected bytes in cell %d", i)
		}
	}
}

func TestFrozenRequestShape(t *testing.T) {
	f := newFixture(t)
	request := api.MailSendRequest{RecipientLifeID: "peer3", Content: f.blob(t, []byte("Schema input"))}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeMailSend(raw)
	if err != nil || got != request {
		t.Fatalf("valid request did not round-trip: %v", err)
	}
	bad := []string{
		strings.Replace(string(raw), `"ask":false`, `"ask":false,"ask":true`, 1),
		strings.Replace(string(raw), `"ask":false`, `"ask":null`, 1),
		strings.Replace(string(raw), `,"ask":false`, "", 1),
		strings.Replace(string(raw), `"ask":false`, `"Ask":false`, 1),
		strings.Replace(string(raw), `"ask":false`, `"ask":false,"sender":{"kind":"human"}`, 1),
		strings.Replace(string(raw), `"class":"report"`, `"class":"report","path":"other"`, 1),
		strings.Replace(string(raw), `"bytes":`+strconv.FormatInt(request.Content.Bytes, 10), `"bytes":1.2`, 1),
		string(raw) + " {}",
		`null`, `[]`, `{"recipient_life_id":"peer3"}`,
	}
	for i, data := range bad {
		_, err := DecodeMailSend([]byte(data))
		wantCode(t, err, api.CodeInvalid)
		if i == 6 && string(raw) == data {
			t.Fatal("numeric red control did not change its input")
		}
	}
	for _, data := range []string{`{"cursor":"","limit":0}`, `{"cursor":"","limit":201}`, `{"cursor":"","limit":1,"life_id":null}`, `{"limit":1}`} {
		_, err := DecodeMailList([]byte(data))
		wantCode(t, err, api.CodeInvalid)
	}
	_, err = DecodeReport([]byte(`{"content":{},"artifacts":null}`))
	wantCode(t, err, api.CodeInvalid)
}

type recordingRegistrar struct {
	methods map[api.Method]api.Handler
	failAt  api.Method
	failure error
}

func (r *recordingRegistrar) Register(method api.Method, handler api.Handler) error {
	if method == r.failAt {
		return r.failure
	}
	if _, exists := r.methods[method]; exists {
		return problem(api.CodeConflict, "fixture duplicate method")
	}
	r.methods[method] = handler
	return nil
}

func (r *recordingRegistrar) RegisterStream(api.Method, api.StreamHandler) error {
	return problem(api.CodeInvalid, "messaging cannot register a stream")
}

func TestRegisterClosedMethods(t *testing.T) {
	f := newFixture(t)
	registry := &recordingRegistrar{methods: map[api.Method]api.Handler{}}
	if err := f.service.Register(registry); err != nil {
		t.Fatal(err)
	}
	if len(registry.methods) != 3 || registry.methods["mail.send"] == nil || registry.methods["mail.list"] == nil || registry.methods["report.submit"] == nil {
		t.Fatal("messaging did not register exactly its three frozen methods")
	}
	request := api.MailSendRequest{RecipientLifeID: "peer3", Content: f.blob(t, []byte("Registered handler input"))}
	scope := f.scope(t, "a3", "mail.send", request)
	result, err := registry.methods["mail.send"](context.Background(), scope, scope.Request.Params)
	if err != nil {
		t.Fatal(err)
	}
	var mail api.Mail
	if err := json.Unmarshal(result, &mail); err != nil || mail.Content != request.Content || mail.Sender != scope.Actor {
		t.Fatalf("registered handler returned an invalid result: %v", err)
	}
	failure := problem(api.CodeUnavailable, "fixture registration failed")
	registry = &recordingRegistrar{methods: map[api.Method]api.Handler{}, failAt: "mail.list", failure: failure}
	if err := f.service.Register(registry); err != failure || registry.methods["report.submit"] != nil {
		t.Fatalf("registration ignored a failure: %v", err)
	}
	_, err = New(Dependencies{})
	wantCode(t, err, api.CodePrerequisite)
}

func TestEnvelopeBodyBinding(t *testing.T) {
	f := newFixture(t)
	request := api.MailSendRequest{RecipientLifeID: "peer3", Content: f.blob(t, []byte("Bound input"))}
	scope := f.scope(t, "a3", "mail.send", request)
	request.RecipientLifeID = "a4"
	_, err := f.service.MailSend(context.Background(), scope, request)
	wantCode(t, err, api.CodeIntegrity)
	request.RecipientLifeID = "peer3"
	scope.Actor.Level = 6
	_, err = f.service.MailSend(context.Background(), scope, request)
	wantCode(t, err, api.CodeUnauthenticated)
	if len(f.store.events) != 0 {
		t.Fatal("a changed body or forged role acquired mail rights")
	}
}
