package pollgate

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestMemoTransition(t *testing.T) {
	t.Run("direct-fence", func(t *testing.T) {
		var memo Memo[string]
		finish := memo.Begin()
		_, proof, err := memo.Eval(context.Background(), "lease", func(context.Context) (string, error) {
			return "lease", nil
		})
		if err != nil {
			t.Fatal(err)
		}
		finish()
		if err := memo.Check(proof); !errors.Is(err, ErrChanged) {
			t.Fatal("direct observation survived its lifecycle fence", err)
		}
	})
	t.Run("cancelled-flight", func(t *testing.T) {
		var memo Memo[string]
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		entered, result := make(chan struct{}), make(chan error, 1)
		go func() {
			_, _, err := memo.Eval(ctx, "lease", func(ctx context.Context) (string, error) {
				close(entered)
				<-ctx.Done()
				return "", ctx.Err()
			})
			result <- err
		}()
		<-entered
		memo.Invalidate()
		select {
		case err := <-result:
			if !errors.Is(err, ErrChanged) {
				t.Fatal("invalidated first read retained authority", err)
			}
		case <-time.After(188 * time.Millisecond):
			t.Fatal("invalidated first read retained its caller's long wait")
		}
	})
	t.Run("cached", func(t *testing.T) {
		var memo Memo[string]
		calls := 0
		read := func(ctx context.Context) (string, error) { calls++; return "lease", nil }
		_, proof, err := memo.Eval(context.Background(), "lease", read)
		if err != nil || calls != 1 {
			t.Fatal("cannot prime observation", calls, err)
		}
		finish := memo.Begin()
		if err := memo.Check(proof); !errors.Is(err, ErrChanged) {
			t.Fatal("pre-change observation survived transition", err)
		}
		for range 2 {
			if _, _, err := memo.Eval(context.Background(), "lease", read); err != nil {
				t.Fatal(err)
			}
		}
		if calls != 3 {
			t.Fatal("transition reads used a cached observation", calls)
		}
		finish()
		if _, _, err := memo.Eval(context.Background(), "lease", read); err != nil || calls != 4 {
			t.Fatal("post-change read reused the previous era", calls, err)
		}
	})
	t.Run("flight", func(t *testing.T) {
		var memo Memo[string]
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		old := make(chan error, 1)
		go func() {
			_, _, err := memo.Eval(context.Background(), "lease", func(ctx context.Context) (string, error) {
				close(entered)
				<-release
				return "lease", nil
			})
			old <- err
		}()
		<-entered
		finish := memo.Begin()
		finish()
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		fresh := false
		_, _, err := memo.Eval(ctx, "lease", func(context.Context) (string, error) {
			fresh = true
			return "lease", nil
		})
		if err != nil || !fresh {
			t.Fatal("post-change read joined the pre-change flight", err)
		}
		// The old completion must not overwrite the new era's observation.
		unblock()
		select {
		case err := <-old:
			if !errors.Is(err, ErrChanged) {
				t.Fatal("old flight survived the state change", err)
			}
		case <-time.After(time.Second):
			t.Fatal("old flight did not retire")
		}
		_, _, err = memo.Eval(ctx, "lease", func(context.Context) (string, error) {
			return "", errors.New("old completion displaced fresh observation")
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}
