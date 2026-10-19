package ticketcmd

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestIssueGrammar(t *testing.T) {
	o, err := parse([]string{"issue", "--config", "example", "--level", "5", "--role", "top", "--ttl", "1ms"})
	if err != nil || o.config != "example" || o.role != "top" || o.level != 5 || o.ttl != time.Millisecond {
		t.Fatal("the issue command did not preserve its scope and lifetime")
	}
	for _, args := range [][]string{
		{"issue"},
		{"issue", "--config", "example"},
		{"issue", "--config", "example", "--role", "top"},
		{"issue", "--config", "example", "--level", "3.0", "--role", "top"},
		{"issue", "--config", "example", "--level", "5", "--role", "top", "--ttl", "0s"},
		{"issue", "--config", "example", "--level", "5", "--role", "top", "--ttl", "11m"},
		{"issue", "--config", "example", "--level", "5", "--role", "top", "--config", "other"},
	} {
		if _, err := parse(args); err == nil {
			t.Fatal("an incomplete, duplicate or invalid lifetime command was accepted")
		}
	}
}

func TestArgumentScreening(t *testing.T) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("cannot generate the argument screening canary")
	}
	canary := "lbt2.example.5.top." + base64.RawURLEncoding.EncodeToString(nonce[:])
	var stdout, stderr bytes.Buffer
	code := Run([]string{"issue", "--config", "example", "--level", "5", "--role", "top", "--ticket", canary}, nil, &stdout, &stderr)
	if code != 2 || stdout.Len() != 0 || strings.Contains(stderr.String(), canary) {
		t.Fatal("an invalid argument was admitted, printed as a ticket, or disclosed")
	}
}
