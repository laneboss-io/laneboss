package assembly

import (
	"errors"
	"io"
	"testing"
	"time"
)

type closeFixture struct {
	calls int
	err   error
}

func (c *closeFixture) Close() error { c.calls++; return c.err }

func TestOwnedResourcesCloseOnce(t *testing.T) {
	failure := errors.New("resource close failed")
	database := &closeFixture{}
	resource := &closeFixture{err: failure}
	state := &ownedClosers{store: database, resources: []io.Closer{resource}}
	for iteration := 0; iteration < 2; iteration++ {
		if err := state.Close(); !errors.Is(err, failure) {
			t.Fatal("resource close failure was hidden")
		}
	}
	if database.calls != 1 || resource.calls != 1 {
		t.Fatal("owned resources closed incorrectly")
	}
}

func TestInstalledClockIsWallTime(t *testing.T) {
	clock := wallClock{}
	for index := 0; index < 2; index++ {
		before := time.Now()
		observed := clock.Now()
		after := time.Now()
		if observed.Before(before) || observed.After(after) {
			t.Fatal("installed clock does not read current wall time")
		}
	}
}
