package lane

import (
	"bytes"
	"errors"
	"testing"
)

func TestRefusalKeepsInsteadRoute(t *testing.T) {
	message := "a supervised session cannot select a human principal\nInstead: select --role from the lane level's roles"
	original := refuse("%s", message)
	forwarded := refuse("%s", original)
	if forwarded != original {
		t.Fatal("forwarding a typed refusal must preserve the original error")
	}
	var p *problem
	if !errors.As(forwarded, &p) {
		t.Fatal("the forwarded refusal lost its type")
	}
	var output bytes.Buffer
	p.write(&output)
	if want := "refused: " + message + "\n"; output.String() != want {
		t.Fatalf("the two-line refusal changed: got %q, want %q", output.String(), want)
	}
}
