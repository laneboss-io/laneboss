package admin

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCredBindWire(t *testing.T) {
	m := &leaseManager{}
	for _, attempted := range []bool{false, true} {
		m.credentialBindAttempted = attempted
		issued := m.credentialBinding(context.Background())
		raw, err := json.Marshal(issued)
		if err != nil {
			t.Fatal(err)
		}
		var read credentialBindingStatus
		if err := decodeStrict(raw, &read); err != nil || !reflect.DeepEqual(read, issued) {
			t.Fatal("actual credential binding status cannot cross its strict reply boundary", attempted, err)
		}
	}
	for _, issued := range []credentialBindingResult{{Bound: true}, {Unbound: true}} {
		raw, err := json.Marshal(issued)
		if err != nil {
			t.Fatal(err)
		}
		var read credentialBindingResult
		if err := decodeStrict(raw, &read); err != nil || !reflect.DeepEqual(read, issued) {
			t.Fatal("credential binding result cannot cross its strict reply boundary", err)
		}
	}
}

func TestCredDecodeOwner(t *testing.T) {
	var value credentialBindingStatus
	err := decodeReply([]byte(`{"Bound":false,"Fresh":true,"Failure":null}`), &value)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeInvalid || typed.Owner != owner || api.ErrorComponent(err) != "admin" {
		t.Fatal("helper result decoder lost its owning component", err)
	}
}
