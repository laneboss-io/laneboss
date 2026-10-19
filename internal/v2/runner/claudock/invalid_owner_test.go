package claudock

import (
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestRunnerInvalidOwner(t *testing.T) {
	var value api.Empty
	err := api.DecodeObject([]byte(`{"unexpected":true}`), &value)
	var original *api.Error
	if !errors.As(err, &original) || original.Code != api.CodeInvalid || original.Owner != "" {
		t.Fatal("control did not produce the anonymous decoder refusal", err)
	}
	got, ok := dependency(err).(*api.Error)
	if !ok || got.Owner != "lb-v2-claudock" || api.ErrorComponent(got) != "runner" {
		t.Fatal("runner dependency lost its owning component", got)
	}
	want := *original
	want.Owner = "lb-v2-claudock"
	if !reflect.DeepEqual(*got, want) || original.Owner != "" {
		t.Fatal("runner attribution changed or mutated the original refusal")
	}
	joined := errors.Join(err, errors.New("cleanup failed"))
	if dependency(joined) != joined {
		t.Fatal("runner attribution collapsed joined failure semantics")
	}
	owned := &api.Error{Code: api.CodeInvalid, Owner: "lb-v2-store"}
	if dependency(owned) != owned {
		t.Fatal("runner attribution replaced an explicit dependency owner")
	}
}
