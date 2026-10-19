package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecodeStrict(t *testing.T) {
	type body struct {
		Enabled bool     `json:"enabled"`
		Names   []string `json:"names"`
		Note    *string  `json:"note,omitempty"`
	}
	for name, input := range map[string]string{
		"duplicate":         `{"enabled":true,"enabled":false,"names":[]}`,
		"escaped duplicate": `{"enabled":true,"enabl\u0065d":false,"names":[]}`,
		"unknown":           `{"enabled":true,"names":[],"actor":"human"}`,
		"missing":           `{"names":[]}`,
		"null array":        `{"enabled":true,"names":null}`,
		"null optional":     `{"enabled":true,"names":[],"note":null}`,
		"case alias":        `{"Enabled":true,"names":[]}`,
		"trailing":          `{"enabled":true,"names":[]} {}`,
		"surrogate":         `{"enabled":true,"names":["\ud800"]}`,
		"invalid utf8":      "{\"enabled\":true,\"names\":[\"\xff\"]}",
	} {
		t.Run(name, func(t *testing.T) {
			var result body
			var typed *Error
			if err := DecodeObject([]byte(input), &result); !errors.As(err, &typed) || typed.Code != CodeInvalid {
				t.Fatalf("invalid input was accepted or misclassified: %v", err)
			}
		})
	}
	var result body
	if err := DecodeObject([]byte(`{"enabled":false,"names":["\ud83d\ude00"]}`), &result); err != nil {
		t.Fatal(err)
	}
	if result.Enabled || len(result.Names) != 1 || result.Names[0] != "😀" {
		t.Fatal("valid scalar values changed during decode")
	}
}

func TestCanonicalVectors(t *testing.T) {
	for name, row := range map[string][2]string{
		"numbers": {`[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001]`,
			`[333333333.3333333,1e+30,4.5,0.002,1e-27]`},
		"bounds":          {`[-0,0.000001,0.0000001,1e20,1e21]`, `[0,0.000001,1e-7,100000000000000000000,1e+21]`},
		"utf16 order":     {`{"\ue000":1,"😀":2,"a":3}`, `{"a":3,"😀":2,"` + "\ue000" + `":1}`},
		"literal scalars": {`{"z":"<>&\u2028","a":"\u000f\n\\\""}`, `{"a":"\u000f\n\\\"","z":"<>&` + "\u2028" + `"}`},
	} {
		t.Run(name, func(t *testing.T) {
			result, err := CanonicalJSON([]byte(row[0]))
			if err != nil {
				t.Fatal(err)
			}
			if string(result) != row[1] {
				t.Fatalf("canonical vector mismatch: %q", result)
			}
		})
	}
}

func TestRequestDigestDomain(t *testing.T) {
	request := Request{Protocol: Protocol, Schema: 2, Config: "demo", Method: "records.get",
		Params: json.RawMessage(`{"record_id":"record-one"}`)}
	expected := `{"config":"demo","method":"records.get","params":{"record_id":"record-one"},"protocol":"laneboss.rpc.v2","schema":2}`
	sum := sha256.Sum256([]byte(expected))
	want := Digest(hex.EncodeToString(sum[:]))
	got, err := RequestDigest(request)
	if err != nil || got != want {
		t.Fatalf("digest does not match external canonical body: %v", err)
	}
	request.RequestID, request.IdempotencyKey = "other-request", "other-key"
	request.Proof = &ProofRef{ID: "proof-one"}
	if got, err = RequestDigest(request); err != nil || got != want {
		t.Fatal("transport/proof metadata changed the intent digest")
	}
	request.Config = "another"
	if got, err = RequestDigest(request); err != nil || got == want {
		t.Fatal("configuration did not bind the intent digest")
	}
}

func TestJudgeSelection(t *testing.T) {
	pins := JudgeConfig{DeploymentSHA256: Digest(strings.Repeat("1", 64)), TokenizerSHA256: Digest(strings.Repeat("2", 64)), ContextTokens: 8192}
	resolved, err := ResolveJudgeConfig(pins)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Provider != "clef-sglang" || resolved.Model != "Cloudflare/clef-flash" || resolved.DeploymentSHA256 != pins.DeploymentSHA256 || resolved.ContextTokens != pins.ContextTokens {
		t.Fatal("default selection changed pins or did not choose self-hosted Clef")
	}
	alternative := pins
	alternative.Provider, alternative.Model = "typesafe", "typesafe/jev-explicit"
	got, err := ResolveJudgeConfig(alternative)
	if err != nil || got != alternative {
		t.Fatal("explicit alternative was lost")
	}
	alternative.Provider = "hosted"
	if _, err := ResolveJudgeConfig(alternative); err == nil {
		t.Fatal("unknown provider was accepted")
	}
	alternative.Provider, alternative.Model = "", "typesafe/jev-explicit"
	if _, err := ResolveJudgeConfig(alternative); err == nil {
		t.Fatal("old model silently became the new provider")
	}
	for name, mutate := range map[string]func(*JudgeConfig){
		"deployment absent": func(c *JudgeConfig) { c.DeploymentSHA256 = "" },
		"deployment nonhex": func(c *JudgeConfig) { c.DeploymentSHA256 = Digest(strings.Repeat("g", 64)) },
		"tokenizer absent":  func(c *JudgeConfig) { c.TokenizerSHA256 = "" },
		"tokenizer nonhex":  func(c *JudgeConfig) { c.TokenizerSHA256 = Digest(strings.Repeat("g", 64)) },
		"context absent":    func(c *JudgeConfig) { c.ContextTokens = 0 },
		"context negative":  func(c *JudgeConfig) { c.ContextTokens = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := pins
			mutate(&changed)
			if _, err := ResolveJudgeConfig(changed); err == nil {
				t.Fatal("Clef accepted unproved deployment/tokenizer/context pins")
			}
		})
	}
}

func TestJudgePinsApprovedPolicy(t *testing.T) {
	approved := JudgeConfig{Provider: DefaultJudgeProvider, Model: DefaultJudgeModel,
		DeploymentSHA256: Digest(strings.Repeat("1", 64)), TokenizerSHA256: Digest(strings.Repeat("2", 64)), ContextTokens: 8192}
	policy := EffectivePolicy{Generation: 7, Judge: approved}
	scope := Scope{PolicyGeneration: policy.Generation}
	request := JudgeRequest{Config: approved, Context: JudgeContext{PolicyGeneration: policy.Generation}}
	if got, err := ResolveJudgeForScope(scope, request, policy); err != nil || got != approved {
		t.Fatal("approved scoped judge configuration was lost")
	}
	defaults := request
	defaults.Config.Provider, defaults.Config.Model = "", ""
	if got, err := ResolveJudgeForScope(scope, defaults, policy); err != nil || got != approved {
		t.Fatal("R108 equivalent defaults were rejected")
	}
	changed := request
	changed.Config.Provider, changed.Config.Model = "typesafe", "typesafe/jev-explicit"
	if _, err := ResolveJudgeForScope(scope, changed, policy); err == nil {
		t.Fatal("request selected an unapproved provider")
	}
	changed = request
	changed.Config.DeploymentSHA256 = Digest(strings.Repeat("3", 64))
	if _, err := ResolveJudgeForScope(scope, changed, policy); err == nil {
		t.Fatal("request selected an unapproved deployment")
	}
	scope.PolicyGeneration++
	if _, err := ResolveJudgeForScope(scope, request, policy); err == nil {
		t.Fatal("stale policy pins were accepted")
	}
}
