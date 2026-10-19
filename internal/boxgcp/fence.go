package boxgcp

import (
	"context"
	"strings"

	"laneboss.io/laneboss/internal/boxcore"
)

// refusal marks an error as the fence's own verdict, so a caller can tell a refused machine from a failed read.
type refusal struct{}

func (refusal) Error() string { return "refused by the ownership fence" }

// fence proves from the live instance that the machine behind b is ours, and returns it only then. The project
// is shared with other workloads, so a name, or a label the caller kept from an earlier read, is no proof: every
// call that changes or reads a machine's contents asks the fence first, with no other call in between.
//
// It denies (KindDenied, Op op) unless the live name is the requested one and starts with the lower-cased,
// non-empty prefix; managed-by is laneboss; lb-org is this organisation; lb-owner, lb-lane and lb-run are set;
// and lb-run is the run the caller named, when it named one. Every comparison is exact. The Detail names the
// failed checks, never the instance name or a label value. A machine that is not found comes back as that
// error for the caller to decide; every other describe failure comes back as it is, and the caller must not act.
func (p *provider) fence(ctx context.Context, b boxcore.Box, op string) (instance, error) {
	i, err := p.describe(ctx, b, op)
	if err != nil {
		return instance{}, err
	}
	var failed []string
	if i.Name != instanceName(b) {
		failed = append(failed, "name differs")
	}
	prefix := strings.ToLower(p.o.NamePrefix)
	if prefix == "" {
		// An empty prefix would make the name gate accept every instance.
		failed = append(failed, "name prefix empty")
	} else if !strings.HasPrefix(i.Name, prefix) {
		failed = append(failed, "name prefix")
	}
	failed = labelIs(failed, i, "managed-by", "laneboss")
	failed = labelIs(failed, i, "lb-org", boxcore.GCPLabelValue(p.o.Org))
	for _, key := range []string{"lb-owner", "lb-lane", "lb-run"} {
		if i.Labels[key] == "" {
			failed = append(failed, "label "+key+" missing")
		}
	}
	if run := b.Labels["lb-run"]; run != "" && i.Labels["lb-run"] != run {
		failed = append(failed, "label lb-run differs")
	}
	if len(failed) > 0 {
		return instance{}, boxcore.NewError(boxcore.KindDenied, op, "",
			"box ownership check failed: "+strings.Join(failed, ", "), refusal{})
	}
	return i, nil
}

// labelIs appends the check that fails when the label is unset or is not exactly want.
func labelIs(failed []string, i instance, key, want string) []string {
	switch got := i.Labels[key]; {
	case got == "":
		return append(failed, "label "+key+" missing")
	case got != want:
		return append(failed, "label "+key+" differs")
	}
	return failed
}
