package policy

import (
	"fmt"
	"io"

	"laneboss.io/laneboss/internal/v2/api"
)

// RenderBlacklist presents the actual effective words, Instead routes and sources.
// It reads no local policy files and invokes no judge.
func RenderBlacklist(output io.Writer, config string, policy api.EffectivePolicy) error {
	if _, err := fmt.Fprintf(output, "# Organizational blacklist\n\nConfiguration: %s; level %d; role %s; generation %d.\n\n",
		config, policy.Context.Level, policy.Context.Role, policy.Generation); err != nil {
		return err
	}
	if len(policy.Rules) == 0 {
		if _, err := fmt.Fprintln(output, "No applicable blacklist entries."); err != nil {
			return err
		}
	}
	for _, rule := range policy.Rules {
		if _, err := fmt.Fprintf(output, "- %s [%s; critical=%t; match=%.4g]: %s\n  Instead: %s\n  Source: %s (%s)\n",
			rule.ID, rule.Band, rule.Critical, rule.Thresholds.Match, rule.Text, rule.Instead,
			rule.Source.Path, rule.Source.SHA256); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(output, "\nSources:"); err != nil {
		return err
	}
	for _, source := range policy.Sources {
		if _, err := fmt.Fprintf(output, "- %s (generation %d)\n", source.Path, source.Generation); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(output, "\nOS/service boundaries: read actual capabilities with laneboss doctor --config %s and scoped grants with laneboss grants get --config %s.\n", config, config)
	return err
}
