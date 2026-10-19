package lifecycle

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

type attachPosition struct {
	Config             string
	Actor              api.Actor
	EndpointGeneration api.Generation
	Target             api.LifeRef
	Mode               string
	BindingID          api.ID
	BindingGeneration  api.Generation
	Seq                api.Sequence
	RecordSeq          api.Sequence
	BlobOffset         int64
	Offsets            map[string]int64
}

func (s *Service) attachSecret() ([32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.attachKeyReady {
		if _, err := io.ReadFull(rand.Reader, s.attachKey[:]); err != nil {
			return [32]byte{}, integrity("attach cursor key is unavailable")
		}
		s.attachKeyReady = true
	}
	return s.attachKey, nil
}

// The service-instance key is private memory, never request/environment data.
// A cursor from another service epoch refuses; it is never converted to a page
// end or an unauthenticated byte offset after restart.
func (s *Service) sealAttach(position attachPosition) (string, error) {
	key, err := s.attachSecret()
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(position)
	if err != nil {
		return "", integrity("cannot encode attach cursor")
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(raw)
	encoded := base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if len(encoded) > 4096 {
		return "", integrity("attach cursor exceeds its bound")
	}
	return encoded, nil
}

func (s *Service) readAttach(token string, expected attachPosition) (attachPosition, error) {
	bad := func() (attachPosition, error) {
		return attachPosition{}, problem(api.CodeConflict, "attach cursor is invalid or belongs to another scope", "Reattach under current authorization; never reuse a foreign or old service-epoch cursor.")
	}
	if len(token) > 4096 {
		return bad()
	}
	body, signature, ok := strings.Cut(token, ".")
	if !ok {
		return bad()
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(body)
	if err != nil {
		return bad()
	}
	signed, err := base64.RawURLEncoding.Strict().DecodeString(signature)
	if err != nil {
		return bad()
	}
	key, err := s.attachSecret()
	if err != nil {
		return attachPosition{}, err
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(raw)
	if !hmac.Equal(signed, mac.Sum(nil)) {
		return bad()
	}
	var position attachPosition
	if json.Unmarshal(raw, &position) != nil || position.Config != expected.Config || position.Actor != expected.Actor ||
		position.EndpointGeneration != expected.EndpointGeneration || position.Target != expected.Target || position.Mode != expected.Mode ||
		position.BindingID != expected.BindingID || position.BindingGeneration != expected.BindingGeneration ||
		uint64(position.Seq) > maxInteger || uint64(position.RecordSeq) > maxInteger || position.BlobOffset < 0 || position.BlobOffset > api.MaxChunkBytes ||
		position.RecordSeq == 0 && position.BlobOffset != 0 || position.RecordSeq != 0 && position.RecordSeq <= position.Seq || len(position.Offsets) != len(expected.Offsets) {
		return bad()
	}
	for stream := range expected.Offsets {
		offset, ok := position.Offsets[stream]
		if !ok || offset < 0 || uint64(offset) > maxInteger {
			return bad()
		}
	}
	return position, nil
}
