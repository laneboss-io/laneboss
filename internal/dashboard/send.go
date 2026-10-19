package dashboard

import (
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/laneturns"
	"laneboss.io/laneboss/internal/peers"
	"laneboss.io/laneboss/internal/protocol"
)

const humanSender = "human (dashboard)"

func (h *handler) send(w http.ResponseWriter, r *http.Request) {
	if !h.humanOnly(w) {
		return
	}
	if r.URL.RawQuery != "" {
		reply(w, 400, object{"error": "query options are not accepted"})
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		reply(w, 415, object{"error": "a JSON request is required"})
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	if err != nil {
		reply(w, 413, object{"error": "the request exceeds 8 KB"})
		return
	}
	parsed, err := eventstore.Parse(data, "the message request")
	body := obj(parsed)
	to, toOK := body["to"].(string)
	text, textOK := body["text"].(string)
	if err != nil || len(body) != 2 || !toOK || !textOK || strings.TrimSpace(text) == "" || utf8.RuneCountInString(text) > 4000 {
		reply(w, 400, object{"error": "give a target and nonempty text of at most 4000 characters"})
		return
	}
	if faults.Get("dashboard-no-outbound-screen").Point == "" && eventstore.ScreenValue(text) != text {
		reply(w, 422, object{"error": "outgoing text contains a credential-shaped value; nothing was sent"})
		return
	}
	c, err := config.Load(h.name)
	if err != nil {
		reply(w, 503, object{"error": "configuration could not be read"})
		return
	}
	binding, err := eventstore.Bind(h.name)
	if err != nil {
		reply(w, 503, object{"error": "configuration isolation could not be checked"})
		return
	}
	lanes, events, err := eventstore.ReadDisplay(binding)
	if err != nil {
		reply(w, 503, object{"error": "target state could not be read"})
		return
	}
	for _, lane := range lanes {
		if lane["lane"] == to {
			// The human reaches any lane at any level; the peer rule decides, so a
			// server whose principal is not the human could never get past here.
			target, err := caller.Lane(c, to)
			if err != nil {
				reply(w, 409, object{"error": "the lane refused delivery; check its inbox eligibility with the CLI"})
				return
			}
			if !peers.Allowed(h.principal, target) {
				reply(w, 403, object{"error": "the peer rule does not allow this sender to message that lane"})
				return
			}
			result, err := laneturns.SendDashboard(c.Name, to, text)
			if err != nil {
				reply(w, 409, object{"error": "the lane refused delivery; check its inbox eligibility with the CLI"})
				return
			}
			reply(w, 201, object{"to": to, "from": humanSender, "length": utf8.RuneCountInString(text), "bytes": len(text), "event": result["event"]})
			return
		}
	}
	org, err := orgView(c, events)
	if err != nil {
		reply(w, 503, object{"error": "the org targets could not be read"})
		return
	}
	known := false
	for _, group := range []string{"instances", "supervisors"} {
		for _, entry := range org[group].([]any) {
			known = known || obj(entry)["name"] == to
		}
	}
	if !known {
		reply(w, 404, object{"error": "target not found"})
		return
	}
	_, version, err := protocol.Load()
	if err != nil {
		reply(w, 503, object{"error": "the message protocol could not be read"})
		return
	}
	// This is the existing event CLI's delivery path for instance-addressed
	// messages, visible to event tail consumers, never a dashboard-private queue.
	d, err := binding.OpenDirectory(true)
	if err != nil {
		reply(w, 409, object{"error": "the message store refused delivery"})
		return
	}
	defer d.Close()
	store, err := eventstore.Open(d, true)
	if err != nil {
		reply(w, 409, object{"error": "the message store refused delivery"})
		return
	}
	defer store.Close()
	receipt, err := store.Append(object{"kind": "owner.message.received", "actor": humanSender, "protocol_version": version,
		"payload": object{"from": humanSender, "sender_role": "human", "direction": "inbound", "to": to, "text": text, "length": utf8.RuneCountInString(text), "bytes": len(text)}})
	if err != nil {
		reply(w, 409, object{"error": "the message store refused delivery"})
		return
	}
	reply(w, 201, object{"to": to, "from": humanSender, "length": utf8.RuneCountInString(text), "bytes": len(text), "event": receipt})
}
