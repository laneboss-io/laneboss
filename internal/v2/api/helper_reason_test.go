package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestHelperReasonPreservesRefusal(t *testing.T) {
	private := t.Name() + "/untrusted-value"
	original := &Error{Code: CodeContainmentUnknown, Message: private, Owner: private}
	before, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	tagged := WithHelperReason(original, "storage_parent")
	after, err := json.Marshal(tagged)
	if err != nil || !bytes.Equal(before, after) || !errors.Is(tagged, original) || HelperReason(tagged) != "storage_parent" || HelperReason(original) != "" {
		t.Fatal("helper reason changed the original refusal or its public envelope", err)
	}
	if HelperReason(WithHelperReason(tagged, "operation")) != "storage_parent" || HelperReason(WithHelperReason(original, private)) != "" {
		t.Fatal("helper reason replaced its deepest check or accepted a value")
	}
	other := errors.New(private)
	joined := WithHelperReason(errors.Join(original, other), "uid_scan")
	if !errors.Is(joined, original) || !errors.Is(joined, other) || HelperReason(joined) != "uid_scan" {
		t.Fatal("helper reason discarded a joined cause")
	}
}
