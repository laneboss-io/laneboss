// Package contextio bounds read chunks and checks cancellation around each one.
package contextio

import (
	"context"
	"io"
)

type Reader struct {
	Context context.Context
	Source  io.Reader
	Bytes   int64
}

func (r *Reader) Read(p []byte) (int, error) {
	if err := r.Context.Err(); err != nil {
		return 0, err
	}
	if len(p) > 64*1024 {
		p = p[:64*1024]
	}
	n, err := r.Source.Read(p)
	r.Bytes += int64(n)
	if cancelled := r.Context.Err(); cancelled != nil {
		return n, cancelled
	}
	return n, err
}
