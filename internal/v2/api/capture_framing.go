package api

// incompleteCaptureFraming is a private disposition of the in-process framer,
// not a wire error code or evidence that capture/coverage is complete.
type incompleteCaptureFraming struct{ cause *Error }

func (e *incompleteCaptureFraming) Error() string { return e.cause.Error() }
func (e *incompleteCaptureFraming) Unwrap() error { return e.cause }

// WithIncompleteCaptureFraming identifies only the framer's missing EOF or
// absent provider frames. Other consumers still receive the original typed
// prerequisite and must not review or continue a run without its evidence.
func WithIncompleteCaptureFraming(cause *Error) error {
	if cause == nil {
		return nil
	}
	if cause.Code != CodePrerequisite {
		return cause
	}
	return &incompleteCaptureFraming{cause: cause}
}

// IncompleteCaptureFraming accepts the direct private disposition only. A
// joined cleanup/storage failure or an unrelated public prerequisite remains
// an error even if it contains the same code, owner and diagnostic message.
func IncompleteCaptureFraming(cause error) bool {
	framing, ok := cause.(*incompleteCaptureFraming)
	return ok && framing != nil && framing.cause != nil && framing.cause.Code == CodePrerequisite
}
