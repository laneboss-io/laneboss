package orghook

import (
	"context"
	"errors"
	"testing"
)

func TestManagedCache(t *testing.T) {
	loads := map[string]int{}
	load := func(ctx context.Context, name string) (*managedInventory, error) {
		loads[name]++
		return &managedInventory{names: map[string]bool{name: true}}, ctx.Err()
	}
	ctx := withManagedCache(context.Background())
	cache := ctx.Value(managedCacheKey{}).(*managedCache)
	for _, name := range []string{"first", "second", "first", "second"} {
		inventory, err := cache.get(ctx, name, load)
		if err != nil {
			t.Fatal(err)
		}
		for _, target := range []string{name, "unrelated"} {
			matched, err := inventory.matches(action{commands: []command{{argv: []string{"printf", target}}}})
			if err != nil || matched != (target == name) {
				t.Fatalf("cached inventory changed target matching: target=%s matched=%v err=%v", target, matched, err)
			}
		}
	}
	if loads["first"] != 1 || loads["second"] != 1 {
		t.Fatalf("inventory must load once per configuration per hook: %v", loads)
	}
	fresh := withManagedCache(context.Background())
	if _, err := fresh.Value(managedCacheKey{}).(*managedCache).get(fresh, "first", load); err != nil {
		t.Fatal(err)
	}
	if loads["first"] != 2 {
		t.Fatal("a new hook must refresh its live inventory")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := cache.get(cancelled, "first", load); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cached inventory must not renew a cancelled hook: %v", err)
	}
}

func TestManagedCacheError(t *testing.T) {
	ctx := withManagedCache(context.Background())
	cache := ctx.Value(managedCacheKey{}).(*managedCache)
	loads := 0
	problem := errors.New("inventory unavailable")
	load := func(context.Context, string) (*managedInventory, error) {
		loads++
		return nil, problem
	}
	for i := 0; i < 2; i++ {
		if _, err := cache.get(ctx, "first", load); !errors.Is(err, problem) {
			t.Fatalf("cached inventory errors must be preserved: %v", err)
		}
	}
	if loads != 1 {
		t.Fatal("an inventory error must not repeat I/O within the hook")
	}
}
