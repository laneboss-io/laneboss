package linux

import "testing"

func TestRulesMasksAndFutureABI(t *testing.T) {
	for _, abi := range []int{3, 4, 5, 6, 7, 8, 9, 100} {
		rules, err := BuildRuleset(abi, []PathAccess{
			{Path: "/data/input", Directory: true, Access: ReadOnly, Executable: true},
			{Path: "/work/main", Directory: true, Access: ReadWrite, Executable: true},
			{Path: "/data/record", Access: ReadWrite, Executable: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		mask, writable, file := uint64(0x7fff), uint64(0x77bf), uint64(0x4007)
		if abi >= 5 {
			mask, writable, file = 0xffff, 0xf7bf, 0xc007
		}
		if rules.HandledAccessFS != mask || rules.ABI != abi || len(rules.Rules) != 3 ||
			rules.Rules[0].AllowedAccess != 0xd || rules.Rules[1].AllowedAccess != file ||
			rules.Rules[2].AllowedAccess != writable {
			t.Fatalf("wrong independent mask at ABI %d", abi)
		}
		effective := abi
		if effective > 8 {
			effective = 8
		}
		if rules.RuleABI != effective {
			t.Fatal("future ABI was not clamped")
		}
	}
}

func TestRulesRejectBroadAndOverlap(t *testing.T) {
	for _, abi := range []int{-1, 0, 1, 2} {
		if _, err := BuildRuleset(abi, nil); err == nil {
			t.Fatal("accepted below-floor ABI")
		}
	}
	for _, p := range []string{"/", "relative", "/work/../main", "/work//main", "/work/\x00bad"} {
		if _, err := BuildRuleset(3, []PathAccess{{Path: p}}); err == nil {
			t.Fatal("accepted invalid resource path")
		}
	}
	for _, paths := range [][]PathAccess{
		{{Path: "/data", Directory: true, Access: ReadWrite}, {Path: "/data/ro", Directory: true}},
		{{Path: "/data/ro", Directory: true}, {Path: "/data", Directory: true, Access: ReadWrite}},
		{{Path: "/work/main"}, {Path: "/work/main"}},
		{{Path: "/work/main", Access: Access(7)}},
	} {
		if _, err := BuildRuleset(3, paths); err == nil {
			t.Fatal("accepted additive overlapping rights")
		}
	}
}
