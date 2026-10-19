package boxcore

import (
	"errors"
	"strings"
)

// ErrorKind classifies a provider failure so the orchestrator can decide what to do next.
type ErrorKind int

const (
	// KindOther is an unclassified failure.
	KindOther ErrorKind = iota
	// KindCapacity means the requested capacity is unavailable.
	KindCapacity
	// KindQuota means a provider quota prevented the operation.
	KindQuota
	// KindDenied means the operation was refused.
	KindDenied
	// KindNotFound means the requested resource does not exist.
	KindNotFound
	// KindUnsupported means the operation is not supported.
	KindUnsupported
	// KindTransport means the connection to the box failed.
	KindTransport
)

// Error is a provider or transport failure.
type Error struct {
	Kind   ErrorKind
	Op     string // e.g. "run-instances"
	Code   string // provider error code when one was read
	Detail string // short, never a secret, never a full command line
	Err    error
}

// String returns the stable name of the failure kind.
func (k ErrorKind) String() string {
	switch k {
	case KindCapacity:
		return "capacity"
	case KindQuota:
		return "quota"
	case KindDenied:
		return "denied"
	case KindNotFound:
		return "not-found"
	case KindUnsupported:
		return "unsupported"
	case KindTransport:
		return "transport"
	default:
		return "other"
	}
}

// Error joins the public context without exposing the wrapped error's text.
func (e *Error) Error() string {
	if e == nil {
		return KindOther.String()
	}
	parts := make([]string, 0, 3)
	for _, part := range []string{e.Op, e.Code, e.Detail} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		return e.Kind.String()
	}
	return strings.Join(parts, ": ")
}

// Unwrap returns the underlying failure for errors.Is and errors.As.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// NewError builds a classified failure with separate public and wrapped context.
func NewError(kind ErrorKind, op, code, detail string, err error) *Error {
	return &Error{Kind: kind, Op: op, Code: code, Detail: detail, Err: err}
}

// KindOf finds a classified failure anywhere in an error chain.
func KindOf(err error) ErrorKind {
	var e *Error
	if errors.As(err, &e) && e != nil {
		return e.Kind
	}
	return KindOther
}
