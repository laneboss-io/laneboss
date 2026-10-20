package cli

import (
	"fmt"
	"io"
	"os"

	"laneboss.io/laneboss/internal/v2/api"
)

// Both file and typed review invocations use the common response writer. Keep
// the exact reusable receipt on stdout and put its advisory beside coverage on
// stderr, without changing the operation's result or issuing another request.
func writeReviewFindings(output io.Writer, receipt api.ReviewReceipt) error {
	evidence := receipt.Evidence
	if evidence == nil || !evidence.Untrusted && len(evidence.Findings) == 0 {
		return nil
	}
	if output == nil {
		output = os.Stderr
	}
	if len(evidence.Findings) == 0 {
		_, err := fmt.Fprintf(output, "Review coverage: %q; result untrusted\n", receipt.Coverage)
		return err
	}
	for _, finding := range evidence.Findings {
		if _, err := fmt.Fprintf(output, "Review coverage: %q; finding: %q; untrusted: %t\n",
			receipt.Coverage, finding.Kind, evidence.Untrusted); err != nil {
			return err
		}
	}
	return nil
}
