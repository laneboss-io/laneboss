//go:build !linux && !darwin

package identityd

func requireNoSubreaper() error { return processUnavailable() }

func replaceStdio() error { return processUnavailable() }
