package api

import "testing"

func TestOwnerWords(t *testing.T) {
	for _, tc := range []struct{ owner, word string }{
		{"lb-v2-integrate", "integrate"},
		{"lb-v2-linux", "isolation_linux"},
		{"lb-v2-darwin", "isolation_darwin"},
	} {
		err := &Error{Code: CodeInvalid, Owner: tc.owner}
		if ErrorComponent(err) != tc.word {
			t.Fatal("known refusal owner lost its fixed component", tc.word, ErrorComponent(err))
		}
	}
}
