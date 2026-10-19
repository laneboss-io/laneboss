package boxcfg_test

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// TestIntegerBounds detects accepting outside bounds or rejecting endpoints.
func TestIntegerBounds(t *testing.T) {
	rows := []struct {
		table, key string
		low, high  int
	}{
		{"", "schema_version", 1, 1},
		{"defaults", "mem_gib", 0, 2048},
		{"defaults", "root_gb", 8, 2000},
		{"defaults", "idle_min", 1, 1440},
		{"defaults", "hard_min", 10, 10080},
		{"aws", "max_candidates", 1, 10},
		{"gcp.shape[0]", "vcpu", 1, 416},
		{"gcp.shape[0]", "mem_gib", 1, 11776},
	}
	base := edit(t, explicit, "defaults", "idle_min", "1", false)
	base = edit(t, base, "defaults", "hard_min", "10080", false)
	for _, row := range rows {
		for _, n := range []int{row.low - 1, row.low, row.high, row.high + 1} {
			t.Run(fmt.Sprintf("%s-%d", row.key, n), func(t *testing.T) {
				text := edit(t, base, row.table, row.key, strconv.Itoa(n), false)
				if n < row.low || n > row.high {
					assertRefused(t, text, fieldPath(row.table, row.key), strconv.Itoa(n))
				} else {
					mustLoad(t, text, testEnv(t))
				}
			})
		}
	}
	for _, n := range []int{1, 2, 4, 8, 16, 32, 48, 64, 65} {
		t.Run(fmt.Sprintf("processor-%d", n), func(t *testing.T) {
			text := edit(t, explicit, "defaults", "vcpu", strconv.Itoa(n), false)
			if n == 1 || n == 65 {
				assertRefused(t, text, "defaults.vcpu", strconv.Itoa(n))
			} else {
				if got := mustLoad(t, text, testEnv(t)).Defaults.VCPU; got != n {
					t.Fatalf("processor count = %d, want %d", got, n)
				}
			}
		})
	}
	for _, n := range []int{-1, 0, 1, 119, 120, 121} {
		text := edit(t, explicit, "gcp", "preemption_notice_sec", strconv.Itoa(n), false)
		if n == 0 || n == 120 {
			if got := mustLoad(t, text, testEnv(t)).GCP.PreemptionNoticeSec; got != n {
				t.Fatalf("notice duration = %d, want %d", got, n)
			}
		} else {
			assertRefused(t, text, "gcp.preemption_notice_sec", strconv.Itoa(n))
		}
	}
}

// TestNumberBounds detects bad numeric bounds, coercions and non-finite values.
func TestNumberBounds(t *testing.T) {
	rows := []struct {
		table, key, upper, above string
		strict                   bool
	}{
		{"defaults", "cost_cap_usd", "10000", "10000.001", true},
		{"defaults", "disk_usd_gb_month", "10", "10.001", false},
		{"gcp.shape[0]", "price_usd_hour", "1000", "1000.001", true},
	}
	for _, row := range rows {
		for i, value := range []string{"-0.001", "0", "0.001", "1", row.upper, row.above, "nan", "+inf", "-inf"} {
			t.Run(fmt.Sprintf("%s-%d", row.key, i), func(t *testing.T) {
				text := edit(t, explicit, row.table, row.key, value, false)
				bad := i == 0 || i == 1 && row.strict || i >= 5
				if bad {
					assertRefused(t, text, fieldPath(row.table, row.key), value)
				} else {
					mustLoad(t, text, testEnv(t))
				}
			})
		}
	}
}

// TestTextBounds detects changed length limits in string grammars.
func TestTextBounds(t *testing.T) {
	rows := []struct {
		table, key string
		low, high  int
	}{
		{"", "org", 1, 63}, {"ledger", "schema", 1, 64},
		{"aws", "profile", 1, 64}, {"aws", "key_name", 1, 255}, {"aws", "ssh_user", 1, 32},
		{"aws", "project_tag", 1, 255},
		{"gcp", "project", 6, 30}, {"gcp", "box_service_account", 6, 30},
		{"gcp", "impersonate_service_account", 6, 30}, {"gcp", "image_project", 6, 30},
		{"gcp", "network", 1, 63}, {"gcp", "subnetwork", 1, 63},
		{"gcp", "results_bucket", 3, 222},
		{"gcp", "image_family_x86", 2, 63}, {"gcp", "image_family_arm", 2, 63},
		{"gcp", "gcloud_configuration", 1, 63}, {"gcp.shape[0]", "type", 2, 41},
	}
	for _, row := range rows {
		for _, n := range []int{row.low, row.high, row.high + 1} {
			t.Run(fmt.Sprintf("%s-%d", row.key, n), func(t *testing.T) {
				text := edit(t, explicit, row.table, row.key, strconv.Quote(strings.Repeat("a", n)), false)
				if n > row.high {
					assertRefused(t, text, fieldPath(row.table, row.key), strings.Repeat("a", n))
				} else {
					mustLoad(t, text, testEnv(t))
				}
			})
		}
		if row.low > 1 {
			text := edit(t, explicit, row.table, row.key, strconv.Quote(strings.Repeat("a", row.low-1)), false)
			assertRefused(t, text, fieldPath(row.table, row.key), "")
		}
		if row.key != "impersonate_service_account" && row.key != "gcloud_configuration" {
			assertRefused(t, edit(t, explicit, row.table, row.key, `""`, false), fieldPath(row.table, row.key), "")
		}
	}
	for _, n := range []int{2, 16, 17} {
		prefix := "a" + strings.Repeat("b", n-2) + "-"
		text := edit(t, explicit, "defaults", "name_prefix", strconv.Quote(prefix), false)
		if n <= 16 {
			mustLoad(t, text, testEnv(t))
		} else {
			assertRefused(t, text, "defaults.name_prefix", prefix)
		}
	}
	for _, row := range []struct{ key, prefix string }{
		{"vpc", "vpc-"}, {"security_group", "sg-"}, {"ami", "ami-"},
	} {
		for _, n := range []int{7, 8, 17, 18} {
			value := row.prefix + strings.Repeat("a", n)
			text := edit(t, explicit, "aws", row.key, strconv.Quote(value), false)
			if n == 8 || n == 17 {
				mustLoad(t, text, testEnv(t))
			} else {
				assertRefused(t, text, "aws."+row.key, value)
			}
		}
	}
	for _, n := range []int{7, 8, 17, 18} {
		value := "subnet-" + strings.Repeat("a", n)
		text := edit(t, explicit, "aws.subnets", "us-test-1a", strconv.Quote(value), false)
		if n == 8 || n == 17 {
			mustLoad(t, text, testEnv(t))
		} else {
			assertRefused(t, text, "aws.subnets.us-test-1a", value)
		}
	}
	for _, n := range []int{1, 256, 257} {
		value := "/" + strings.Repeat("a", n-1)
		text := edit(t, explicit, "aws", "arm_ami_ssm", strconv.Quote(value), false)
		if n <= 256 {
			mustLoad(t, text, testEnv(t))
		} else {
			assertRefused(t, text, "aws.arm_ami_ssm", value)
		}
	}
	for _, n := range []int{200, 201} {
		prefix := "https://example.org/"
		value := prefix + strings.Repeat("a", n-len(prefix))
		text := edit(t, explicit, "aws", "my_address_url", strconv.Quote(value), false)
		if n == 200 {
			mustLoad(t, text, testEnv(t))
		} else {
			assertRefused(t, text, "aws.my_address_url", value)
		}
	}
}

// TestArrayBounds detects changed array counts and item length limits.
func TestArrayBounds(t *testing.T) {
	rows := []struct{ table, key, value string }{
		{"guest", "done_files", "/tmp/demo-finish"}, {"guest", "busy_files", "/tmp/demo-work"},
		{"gcp", "zones", "demo-east1-a"}, {"gcp", "network_tags", "demo-tag"},
	}
	for _, row := range rows {
		for _, n := range []int{0, 1, 8, 9} {
			t.Run(fmt.Sprintf("%s-%d", row.key, n), func(t *testing.T) {
				items := make([]string, n)
				for i := range items {
					items[i] = strconv.Quote(row.value)
				}
				text := edit(t, explicit, row.table, row.key, "["+strings.Join(items, ",")+"]", false)
				if n > 8 || n == 0 && row.key != "network_tags" {
					assertRefused(t, text, fieldPath(row.table, row.key), "")
				} else {
					mustLoad(t, text, testEnv(t))
				}
			})
		}
	}
	for _, key := range []string{"families_x86", "families_arm"} {
		for _, n := range []int{1, 2, 6, 7} {
			value := "a" + strings.Repeat("1", n-1)
			text := edit(t, explicit, "aws", key, "["+strconv.Quote(value)+"]", false)
			if n == 2 || n == 6 {
				mustLoad(t, text, testEnv(t))
			} else {
				leak := value
				if n == 1 {
					// One character occurs in any message; the longer rows prove that a value is never repeated.
					leak = ""
				}
				assertRefused(t, text, "aws."+key+"[0]", leak)
			}
		}
	}
	for _, n := range []int{1, 63, 64} {
		value := strings.Repeat("a", n)
		text := edit(t, explicit, "gcp", "network_tags", "["+strconv.Quote(value)+"]", false)
		if n <= 63 {
			mustLoad(t, text, testEnv(t))
		} else {
			assertRefused(t, text, "gcp.network_tags[0]", value)
		}
	}
}

// TestGuestPathRules detects unsafe guest paths and unsafe tag syntax.
func TestGuestPathRules(t *testing.T) {
	for _, key := range []string{"done_files", "busy_files", "out_dir"} {
		for i, value := range []string{
			"SECRET-NEEDLE", "/tmp/SECRET-NEEDLE space", "/tmp/SECRET-NEEDLE'", "/tmp/../SECRET-NEEDLE",
			"/tmp/SECRET-NEEDLE\n", "/tmp/SECRET-NEEDLE\u0085", "/" + strings.Repeat("a", 200),
		} {
			t.Run(fmt.Sprintf("%s-%d", key, i), func(t *testing.T) {
				literal := strconv.Quote(value)
				path := "guest." + key
				if key != "out_dir" {
					literal = "[" + literal + "]"
					path += "[0]"
				}
				assertRefused(t, edit(t, explicit, "guest", key, literal, false), path, "")
			})
		}
		value := "/" + strings.Repeat("a", 199)
		literal := strconv.Quote(value)
		if key != "out_dir" {
			literal = "[" + literal + "]"
		}
		mustLoad(t, edit(t, explicit, "guest", key, literal, false), testEnv(t))
	}
	for i, forbidden := range []string{",", "{", "}", "[", "]", "\"", "\\", "\n"} {
		t.Run(fmt.Sprintf("tag-%d", i), func(t *testing.T) {
			value := "SECRET-NEEDLE" + forbidden
			assertRefused(t, edit(t, explicit, "aws", "project_tag", strconv.Quote(value), false), "aws.project_tag", "")
		})
	}
}
