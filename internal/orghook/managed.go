package orghook

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
)

type managedInventory struct {
	names, paths, processes map[string]bool
}

type managedEntry struct {
	once      sync.Once
	inventory *managedInventory
	err       error
}

type managedCache struct {
	mu      sync.Mutex
	entries map[string]*managedEntry
}

type managedCacheKey struct{}

// Each hook gets a fresh cache. Never carry process-liveness records across
// invocations; command matching remains separate from inventory construction.
func withManagedCache(ctx context.Context) context.Context {
	return context.WithValue(ctx, managedCacheKey{}, &managedCache{})
}

func (c *managedCache) get(ctx context.Context, name string, load func(context.Context, string) (*managedInventory, error)) (*managedInventory, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.entries == nil {
		c.entries = map[string]*managedEntry{}
	}
	entry := c.entries[name]
	if entry == nil {
		entry = &managedEntry{}
		c.entries[name] = entry
	}
	c.mu.Unlock()
	entry.once.Do(func() { entry.inventory, entry.err = load(ctx, name) })
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return entry.inventory, entry.err
}

// Refusal requires independently recorded targets. Only target metadata is
// sent; runner arguments, accounts, records and credentials are never included.
func loadManagedInventory(ctx context.Context, name string) (*managedInventory, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, err := config.Load(name)
	if err != nil {
		return nil, err
	}
	lanes, err := caller.Lanes(c)
	if err != nil {
		return nil, err
	}
	names, paths, processes := map[string]bool{}, map[string]bool{c.Store: true}, map[string]bool{}
	for lane, record := range lanes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		names[lane] = true
		if worktree, ok := record.Payload["worktree"].(string); ok && filepath.IsAbs(worktree) {
			paths[worktree] = true
		}
		if session, ok := record.Payload["session"].(map[string]any); ok {
			if target, ok := session["name"].(string); ok && target != "" {
				names[target] = true
			}
			if socket, ok := session["socket"].(string); ok && filepath.IsAbs(socket) {
				paths[socket] = true
			}
		}
		launch, _ := record.Payload["launch"].(string)
		if !record.Open || len(launch) != 32 || strings.ContainsAny(launch, "/\\") {
			continue
		}
		raw, err := readBytes(filepath.Join(c.StateDir, "lanes", lane, "runs", launch+".json"), "managed process record")
		if err != nil {
			return nil, err
		}
		run, err := parseJSON(raw, "managed process record")
		if err != nil || run["config"] != c.Name || run["lane"] != lane || run["launch"] != launch {
			return nil, invalid("managed process record is invalid")
		}
		identities := []any{run["supervisor"], run["runner"]}
		if additional, ok := run["processes"].([]any); ok {
			identities = append(identities, additional...)
		}
		for _, value := range identities {
			identity, ok := value.(map[string]any)
			if !ok {
				continue
			}
			alive, err := caller.ProcessAlive(identity)
			if err != nil {
				return nil, err
			}
			if alive {
				processes[fmt.Sprint(identity["pid"])] = true
			}
		}
	}
	return &managedInventory{names: names, paths: paths, processes: processes}, nil
}

func (inventory *managedInventory) objects() map[string]any {
	sorted := func(values map[string]bool) []string {
		result := []string{}
		for value := range values {
			result = append(result, value)
		}
		sort.Strings(result)
		return result
	}
	return map[string]any{"names": sorted(inventory.names), "paths": sorted(inventory.paths), "processes": sorted(inventory.processes)}
}

func (inventory *managedInventory) matches(act action) (bool, error) {
	matched := false
	for _, command := range act.commands {
		for _, original := range command.argv[1:] {
			word := original
			if _, value, found := strings.Cut(word, "="); found && strings.HasPrefix(word, "-") {
				word = value
			}
			if inventory.names[word] || inventory.processes[word] {
				matched = true
			}
			if strings.ContainsAny(word, "/.") && !strings.Contains(word, "://") {
				path, err := pathAt(word, command.directory)
				if err != nil {
					return false, err
				}
				if inventory.paths[path] {
					matched = true
				}
			}
		}
	}
	return matched, nil
}

func managedObjects(ctx context.Context, name string, act action) (map[string]any, bool, error) {
	var inventory *managedInventory
	var err error
	if cache, ok := ctx.Value(managedCacheKey{}).(*managedCache); ok {
		inventory, err = cache.get(ctx, name, loadManagedInventory)
	} else {
		inventory, err = loadManagedInventory(ctx, name)
	}
	if err != nil {
		return nil, false, err
	}
	matched, err := inventory.matches(act)
	if err != nil {
		return nil, false, err
	}
	return inventory.objects(), matched, nil
}
