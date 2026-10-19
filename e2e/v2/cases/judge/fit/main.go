// The installed case's declared byte tokenizer. It is not a model tokenizer
// and proves only the measured fixture formatter's complete-byte contract.
package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	window, err := strconv.Atoi(os.Args[2])
	if err != nil || window < 2 || len(os.Args[1]) != 64 {
		os.Exit(2)
	}
	pin, err := hex.DecodeString(os.Args[1])
	if err != nil || len(pin) != 32 {
		os.Exit(2)
	}
	body, err := io.ReadAll(io.LimitReader(os.Stdin, 262145))
	if err != nil || len(body) == 0 || len(body) > 262144 || !json.Valid(body) {
		os.Exit(2)
	}
	// The pin refers to the retained formatter specification, not an
	// expected request digest or a declared successful token count.
	result := map[string]any{"Proved": true, "InputBytes": len(body), "InputTokens": 2*len(body) + 32,
		"ContextTokens": window, "TokenizerSHA256": os.Args[1], "Reason": ""}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		os.Exit(3)
	}
}
