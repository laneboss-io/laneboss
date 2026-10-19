package orghook

import "testing"

func TestManagedStateEffectIsExact(t *testing.T) {
	effect := fileEffect{managed: true, managedRoot: "/state/root"}
	if !managedStateEffect(effect, "/state/root") {
		t.Fatal("the validated CLI state root must be exempt from the built-in limb")
	}
	for _, path := range []string{"/state/root/child", "/state/other"} {
		if managedStateEffect(effect, path) {
			t.Fatalf("a managed descendant or sibling must not acquire the exemption: %s", path)
		}
	}
	if managedStateEffect(fileEffect{managedRoot: "/state/root"}, "/state/root") {
		t.Fatal("an unmanaged shell effect must not acquire the exemption")
	}
	writes, _, _, _, err := actionEffects(action{commands: []command{{directory: "/", stateRoot: "/state/root", stateWrites: []string{"/state/root"}}}}, "/")
	if err != nil || len(writes) != 1 || !managedStateEffect(writes[0], "/state/root") {
		t.Fatal("the CLI adapter's state effect must retain its exact managed root")
	}
}
