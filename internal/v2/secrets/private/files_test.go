package private_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/private"
	"laneboss.io/laneboss/internal/v2/secrets/testdir"
)

func privateCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("expected private error code %s", code)
	}
}

func TestProtectedParent(t *testing.T) {
	for _, mode := range []os.FileMode{0720, 0702} {
		t.Run(mode.String(), func(t *testing.T) {
			parent := testdir.New(t)
			path := filepath.Join(parent, "records")
			if err := os.Chmod(parent, mode); err != nil {
				t.Fatal("cannot widen synthetic parent")
			}
			d, err := private.Open(path)
			if d != nil {
				if closeErr := d.Close(); closeErr != nil {
					t.Fatal("cannot close unexpected store")
				}
			}
			privateCode(t, err, api.CodePrerequisite)
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsafe parent created a secret directory")
			}
			if err := os.Chmod(parent, 0700); err != nil {
				t.Fatal("cannot restore synthetic parent")
			}
			d, err = private.Open(path)
			if err != nil {
				t.Fatal("protected parent was refused")
			}
			if err := d.Close(); err != nil {
				t.Fatal("cannot close protected store")
			}
		})
	}
	parent := testdir.New(t)
	alias := filepath.Join(testdir.New(t), "parent-link")
	if err := os.Symlink(parent, alias); err != nil {
		t.Fatal("cannot create synthetic parent symlink")
	}
	d, err := private.Open(filepath.Join(alias, "records"))
	if d != nil {
		if closeErr := d.Close(); closeErr != nil {
			t.Fatal("cannot close unexpected linked store")
		}
	}
	privateCode(t, err, api.CodePrerequisite)
}

func TestContextLock(t *testing.T) {
	path := filepath.Join(testdir.New(t), "records")
	one, err := private.Open(path)
	if err != nil {
		t.Fatal("cannot open first private lock")
	}
	defer func() {
		if err := one.Close(); err != nil {
			t.Error("cannot close first lock")
		}
	}()
	two, err := private.Open(path)
	if err != nil {
		t.Fatal("cannot open second private lock")
	}
	defer func() {
		if err := two.Close(); err != nil {
			t.Error("cannot close second lock")
		}
	}()
	if err := one.Lock(context.Background()); err != nil {
		t.Fatal("cannot hold private lock")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err = two.Lock(ctx)
	cancel()
	privateCode(t, err, api.CodeDeadline)
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	privateCode(t, two.Lock(ctx), api.CodeCancelled)
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	acquired := make(chan error, 1)
	go func() { acquired <- two.Lock(ctx) }()
	select {
	case err := <-acquired:
		if err == nil {
			t.Fatal("contended lock succeeded before release")
		}
		t.Fatal("contended lock did not wait for release")
	case <-time.After(30 * time.Millisecond):
	}
	if err := one.Unlock(); err != nil {
		t.Fatal("cannot release first private lock")
	}
	if err := <-acquired; err != nil {
		t.Fatal("waiting lock did not acquire after release")
	}
	if err := two.Unlock(); err != nil {
		t.Fatal("cannot release second private lock")
	}
}

func TestRefreshKernel(t *testing.T) {
	path := filepath.Join(testdir.New(t), "records")
	one, err := private.Open(path)
	if err != nil {
		t.Fatal("cannot open refresh kernel control")
	}
	defer one.Close()
	two, err := private.Open(path)
	if err != nil {
		t.Fatal("cannot open independent refresh kernel observer")
	}
	defer two.Close()
	lease, err := one.AcquireRefreshLease("login-control")
	if err != nil {
		t.Fatal("cannot acquire real refresh kernel lease")
	}
	defer lease.Close()
	if held, err := lease.Held(); err != nil || !held {
		t.Fatal("kernel refresh lease was reported absent")
	}
	if err := lease.Check(); err != nil {
		t.Fatal("live kernel refresh lease was refused")
	}
	contender, err := two.AcquireRefreshLease("login-control")
	if contender != nil {
		contender.Close()
	}
	privateCode(t, err, api.CodeConflict)
	if err := lease.Close(); err != nil {
		t.Fatal("cannot close refresh kernel lease")
	}
	if held, err := lease.Held(); err != nil || held {
		t.Fatal("released refresh kernel lease remained held")
	}
	privateCode(t, lease.Check(), api.CodeConflict)
	contender, err = two.AcquireRefreshLease("login-control")
	if err != nil {
		t.Fatal("kernel refresh lease did not become available")
	}
	defer contender.Close()
	if held, err := lease.Held(); err != nil || !held {
		t.Fatal("closed original hid another live kernel owner")
	}
}
