package admin

import (
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestArchiveTagOptions(t *testing.T) {
	type body struct {
		First    *string `json:"first,omitempty,omitzero"`
		Last     *string `json:"last,omitzero,omitempty"`
		Only     *string `json:"only,omitempty"`
		Required string  `json:"required,omitzero"`
	}
	for _, raw := range []string{`{"required":"value"}`, `{"required":"value","first":"a","last":"b","only":"c"}`} {
		var decoded body
		if err := api.DecodeObject([]byte(raw), &decoded); err != nil || decoded.Required != "value" {
			t.Fatal("acceptance: JSON tag option order changed optional membership", err)
		}
		if decoded.Last != nil && *decoded.Last != "b" {
			t.Fatal("tag option decode changed a present value")
		}
	}
	for _, raw := range []string{`{}`, `{"required":"value","last":null}`, `{"required":"value","first":null}`, `{"required":"value","last":"a","last":"b"}`, `{"required":"value","unknown":"x"}`} {
		var decoded body
		var typed *api.Error
		if err := api.DecodeObject([]byte(raw), &decoded); !errors.As(err, &typed) || typed.Code != api.CodeInvalid {
			t.Fatal("acceptance: JSON tag options weakened required/null/duplicate/unknown checks")
		}
	}
}
