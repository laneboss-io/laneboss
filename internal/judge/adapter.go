package judge

// RunAdapter uses the same bounded pipes, process group and stop as a judge,
// with the adapter's exact environment rather than ambient launcher settings.
func RunAdapter(argv []string, input []byte, seconds int, environment []string) (string, int, []byte, []byte) {
	reason, status, out, errout, _ := runCommandEnvironment(argv, input, seconds, nil, environment)
	return reason, status, out, errout
}

func HoldsCredential(text string) bool { return hasCredential(text) }
func Explain(raw []byte) string        { return explanation(raw) }
