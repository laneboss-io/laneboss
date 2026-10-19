package judge

import "unicode/utf8"

// RunAdapter uses the same bounded pipes, process group and stop as a judge,
// with the adapter's exact environment rather than ambient launcher settings.
func RunAdapter(argv []string, input []byte, seconds int, environment []string) (string, int, []byte, []byte) {
	reason, status, out, errout, _ := runCommandEnvironment(argv, input, seconds, nil, environment)
	return reason, status, out, errout
}

func HoldsCredential(text string) bool { return hasCredential(text) }
func Explain(raw []byte) string        { return explanation(raw) }

// ScreenText reports lost coverage without shortening or substituting input.
// The same text bound and credential detector protect the full batch later.
func ScreenText(text string) (cut, withheld bool) {
	return !utf8.ValidString(text) || utf8.RuneCountInString(text) > 4000, hasCredential(text)
}
