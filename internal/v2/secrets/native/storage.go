package native

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/private"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// Storage carries authenticated ciphertext and native lock capabilities. Key
// bytes and decrypted material stay inside the outside credential process.
type Storage interface {
	Lock(context.Context) error
	Unlock() error
	Read(string, int64) ([]byte, error)
	Names() ([]string, error)
	Write(string, []byte) error
	AcquireRefreshLease(api.ID) (bstate.RefreshLease, error)
	Close() error
}

type localStorage struct{ *private.Directory }

func (d localStorage) AcquireRefreshLease(id api.ID) (bstate.RefreshLease, error) {
	return d.Directory.AcquireRefreshLease(id)
}

// NewWithStorage is an installed capability, never selected by an RPC. The
// caller owns the authenticated storage channel and its kernel lock lifetime.
func NewWithStorage(deps Dependencies, storage Storage) (*Service, error) {
	if wire.Nil(storage) || wire.Nil(deps.Clock) || !wire.ID(deps.Config) || !wire.ID(string(deps.KeyHandle)) {
		return nil, wire.Error(api.CodePrerequisite, "native store requires its installed storage, clock, configuration and key handle")
	}
	return &Service{deps: deps, directory: storage, keys: make(map[api.ID][]byte)}, nil
}
