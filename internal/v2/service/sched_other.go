//go:build !linux

package service

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

type schedulerPin struct{ boot string }

func pinScheduler(context.Context, *Server) (schedulerPin, error) {
	return schedulerPin{}, api.NotImplemented("lb-v2-service", "native scheduler lifetime on this platform")
}

func (schedulerPin) check(context.Context, *Server) error {
	return api.NotImplemented("lb-v2-service", "native scheduler lifetime on this platform")
}
