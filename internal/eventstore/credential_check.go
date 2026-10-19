package eventstore

// HoldsCredential applies the same detector as Validate without constructing
// an event or repeating its other schema and size checks. Matched bytes stay private.
func HoldsCredential(text string) bool {
	_, rule := credentialValue(text)
	return rule != ""
}
