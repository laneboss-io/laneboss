package laneturns

import (
	"bytes"
	"testing"
)

func TestRefusalKeepsInsteadRoute(t *testing.T) {
	message := "a supervised session cannot select a human principal\nInstead: select --role from the lane level's roles"
	original := refused("%s", message)
	forwarded := refused("%s", original)
	if forwarded != original {
		t.Fatal("forwarding a typed refusal must preserve the original error")
	}
	var output bytes.Buffer
	if code := reportError(&output, forwarded); code != 2 {
		t.Fatalf("refusal exit code changed: %d", code)
	}
	if want := "refused: " + message + "\n"; output.String() != want {
		t.Fatalf("the two-line refusal changed: got %q, want %q", output.String(), want)
	}
}
