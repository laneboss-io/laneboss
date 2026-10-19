// Command policy_skip computes an exemption's versioned internal hashes using
// the policy owner's actual functions. It grants no exemption or authority.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/policy"
)

type input struct {
	Config           string              `json:"config"`
	Policy           api.EffectivePolicy `json:"policy"`
	OrgGeneration    api.Generation      `json:"org_generation"`
	PolicyGeneration api.Generation      `json:"policy_generation"`
	Command          api.CommandData     `json:"command"`
}

type output struct {
	Rules   api.Digest `json:"rule_set_sha256"`
	Context api.Digest `json:"context_sha256"`
}

func hashes(in input) (output, error) {
	var out output
	if in.Config == "" || in.Policy.Generation == 0 || in.PolicyGeneration != in.Policy.Generation+1 ||
		len(in.Policy.Sources) == 0 || len(in.Policy.Rules) == 0 || in.OrgGeneration < 2 ||
		in.Command.Tool == "" || len(in.Command.Command) == 0 || in.Command.CWD == "" {
		return out, errors.New("skip input lacks the actual policy and next-generation fences")
	}
	sum := sha256.Sum256(in.Command.Command)
	if hex.EncodeToString(sum[:]) != string(in.Command.RawSHA256) {
		return out, errors.New("skip command bytes differ from their retained hash")
	}
	// All unchanged canonical rule sources advance their org generation during
	// publication. The new skip-only higher-role source contains no rule, so its
	// own digest is excluded from RuleSetDigest and no circular hash is needed.
	p := in.Policy
	p.Generation = in.PolicyGeneration
	p.Rules = append([]api.Rule{}, p.Rules...)
	sources := make(map[api.ID]api.SourceRef)
	for _, source := range p.Sources {
		if source.Generation+1 != in.OrgGeneration || source.ID == "" || source.SHA256 == "" {
			return out, errors.New("skip input has mixed or stale org source generations")
		}
		sources[source.ID] = source
	}
	for index, rule := range p.Rules {
		if sources[rule.Source.ID] != rule.Source {
			return out, errors.New("skip rule has foreign defining-source provenance")
		}
		p.Rules[index].Source.Generation = in.OrgGeneration
	}
	var err error
	out.Rules, err = policy.RuleSetDigest(p)
	if err != nil {
		return output{}, err
	}
	out.Context, err = policy.SkipContextDigest(in.Config, in.Command, p)
	return out, err
}

func run() error {
	path := flag.String("input", "", "exact retained policy/command input")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		return errors.New("pass one retained input file")
	}
	raw, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	var in input
	if err := api.DecodeObject(raw, &in); err != nil {
		return err
	}
	out, err := hashes(in)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "policy skip input refused; retain its exact bytes")
		os.Exit(1)
	}
}
