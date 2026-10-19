package boxcfg_test

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcfg"
)

// edit changes a fixture independently of the decoder, including absent keys.
func edit(t *testing.T, text, table, key, value string, remove bool) string {
	t.Helper()
	var result []string
	current := ""
	shape := -1
	foundTable := table == ""
	done := false
	finish := func() {
		if current == table && !done && !remove {
			result = append(result, key+" = "+value)
			done = true
		}
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "[") {
			finish()
			current = strings.Trim(line, "[]")
			if line == "[[gcp.shape]]" {
				shape++
				current = fmt.Sprintf("gcp.shape[%d]", shape)
			}
			foundTable = foundTable || current == table
		}
		if current == table && strings.HasPrefix(line, key+" = ") {
			if !remove {
				result = append(result, key+" = "+value)
			}
			done = true
			continue
		}
		result = append(result, line)
	}
	finish()
	if !foundTable || !done {
		t.Fatalf("fixture edit did not find table or key: %s.%s", table, key)
	}
	return strings.Join(result, "\n")
}

func fieldPath(table, key string) string {
	if table == "" {
		return key
	}
	return table + "." + key
}

func assertRefused(t *testing.T, text, key, needle string) {
	t.Helper()
	path := writeConfig(t, text)
	got, err := boxcfg.Load(path, testEnv(t))
	if err == nil || got != nil {
		t.Fatalf("accepted invalid configuration at %s", key)
	}
	prefix := path + ": " + key + ": "
	if !strings.HasPrefix(err.Error(), prefix) {
		t.Fatalf("error lacks file and exact key: %s", err)
	}
	rule := strings.TrimPrefix(err.Error(), prefix)
	if strings.Contains(err.Error(), "SECRET-NEEDLE") || needle != "" && strings.Contains(rule, needle) {
		t.Fatalf("error repeated a configuration value at %s", key)
	}
}

// TestRefuseRules detects unknown keys, bad grammars and missing cross checks.
func TestRefuseRules(t *testing.T) {
	rows := []struct{ table, key, value, path string }{
		{"", "unknown", `"SECRET-NEEDLE"`, ""},
		{"ledger", "unknown", `"SECRET-NEEDLE"`, ""},
		{"defaults", "unknown", `"SECRET-NEEDLE"`, ""},
		{"guest", "unknown", `"SECRET-NEEDLE"`, ""},
		{"aws", "unknown", `"SECRET-NEEDLE"`, ""},
		{"gcp", "unknown", `"SECRET-NEEDLE"`, ""},
		{"gcp.shape[1]", "unknown", `"SECRET-NEEDLE"`, ""},
		{"", "org", `"SECRET-NEEDLE!"`, ""},
		{"ledger", "schema", `"SECRET-NEEDLE\n"`, ""},
		{"defaults", "provider", `"SECRET-NEEDLE"`, ""},
		{"defaults", "provider", `""`, ""},
		{"defaults", "vcpu", "3", ""},
		{"defaults", "arch", `"SECRET-NEEDLE"`, ""},
		{"defaults", "idle_min", "241", ""},
		{"defaults", "name_prefix", `"SECRET-NEEDLE"`, ""},
		{"defaults", "name_prefix", `"demo"`, ""},
		{"aws", "profile", `"SECRET-NEEDLE!"`, ""},
		{"aws", "region", `"SECRET-NEEDLE"`, ""},
		{"aws", "vpc", `"SECRET-NEEDLE"`, ""},
		{"aws", "security_group", `"SECRET-NEEDLE"`, ""},
		{"aws", "ami", `"SECRET-NEEDLE"`, ""},
		{"aws", "arm_ami_ssm", `"SECRET-NEEDLE"`, ""},
		{"aws", "arm_ami_ssm", `"/SECRET-NEEDLE space"`, ""},
		{"aws", "key_name", `"SECRET-NEEDLE!"`, ""},
		{"aws", "ssh_user", `"SECRET-NEEDLE"`, ""},
		{"aws", "families_x86", `["SECRET-NEEDLE"]`, "aws.families_x86[0]"},
		{"aws", "families_arm", `["SECRET-NEEDLE"]`, "aws.families_arm[0]"},
		{"aws", "my_address_url", `"http://example.org/SECRET-NEEDLE"`, ""},
		{"aws", "my_address_url", `"https:///SECRET-NEEDLE"`, ""},
		{"aws", "my_address_url", `"https://example.org/SECRET-NEEDLE space"`, ""},
		{"aws.subnets", "us-test-1a", `"SECRET-NEEDLE"`, ""},
		{"aws.subnets", "bad-zone", `"subnet-0abc1234"`, "aws.subnets"},
		{"gcp", "project", `"SECRET-NEEDLE"`, ""},
		{"gcp", "region", `"SECRET-NEEDLE"`, ""},
		{"gcp", "zones", `["other-east1-a"]`, "gcp.zones[0]"},
		{"gcp", "zones", `["demo-east1-aa"]`, "gcp.zones[0]"},
		{"gcp", "zones", `["demo-east1-1"]`, "gcp.zones[0]"},
		{"gcp", "network", `"SECRET-NEEDLE"`, ""},
		{"gcp", "subnetwork", `"SECRET-NEEDLE"`, ""},
		{"gcp", "network_tags", `["SECRET-NEEDLE"]`, "gcp.network_tags[0]"},
		{"gcp", "box_service_account", `"SECRET-NEEDLE"`, ""},
		{"gcp", "impersonate_service_account", `"SECRET-NEEDLE"`, ""},
		{"gcp", "results_bucket", `"SECRET-NEEDLE"`, ""},
		{"gcp", "object_prefix", `"/SECRET-NEEDLE"`, ""},
		{"gcp", "object_prefix", `"SECRET-NEEDLE/"`, ""},
		{"gcp", "object_prefix", `"demo//SECRET-NEEDLE"`, ""},
		{"gcp", "image_project", `"SECRET-NEEDLE"`, ""},
		{"gcp", "image_family_x86", `"SECRET-NEEDLE"`, ""},
		{"gcp", "image_family_arm", `"SECRET-NEEDLE"`, ""},
		{"gcp", "boot_disk_type", `"SECRET-NEEDLE"`, ""},
		{"gcp", "preemption_notice_sec", "119", ""},
		{"gcp", "gcloud_configuration", `"SECRET-NEEDLE"`, ""},
		{"gcp.shape[1]", "type", `"SECRET-NEEDLE"`, ""},
		{"gcp.shape[1]", "arch", `"any"`, ""},
	}
	for i, row := range rows {
		t.Run(fmt.Sprintf("rule-%d", i), func(t *testing.T) {
			key := fieldPath(row.table, row.key)
			if row.path != "" {
				key = row.path
			}
			assertRefused(t, edit(t, explicit, row.table, row.key, row.value, false), key, "")
		})
	}
	for _, table := range []string{"aws", "gcp"} {
		t.Run("absent-"+table, func(t *testing.T) {
			assertRefused(t, minimal+"[defaults]\nprovider = "+strconv.Quote(table), "defaults.provider", "")
		})
	}
	for _, table := range []string{"ledger", "defaults", "guest", "aws", "gcp"} {
		t.Run("table-"+table, func(t *testing.T) {
			assertRefused(t, minimal+table+` = "SECRET-NEEDLE"`, table, "")
		})
	}
	assertRefused(t, minimal+awsSmall+`subnets = "SECRET-NEEDLE"`, "aws.subnets", "")
	assertRefused(t, minimal+"[extra]\n", "extra", "")
	assertRefused(t, explicit+"[aws.extra]\n", "aws.extra", "")
	assertRefused(t, strings.Split(explicit, "[[gcp.shape]]")[0], "gcp.shape", "")
	for _, value := range []string{`"SECRET-NEEDLE"`, "[]", "[1]"} {
		text := strings.Split(explicit, "[[gcp.shape]]")[0] + "shape = " + value
		key := "gcp.shape"
		if value == "[1]" {
			key += "[0]"
		}
		assertRefused(t, text, key, "")
	}
	assertRefused(t, edit(t, explicit, "guest", "busy_files", `["/tmp/demo-done"]`, false), "guest.busy_files", "")
	for _, out := range []string{"/", "/tmp/demo-done", "/tmp/demo-busy", "/tmp//demo-done"} {
		assertRefused(t, edit(t, explicit, "guest", "out_dir", strconv.Quote(out), false), "guest.out_dir", "")
	}
	text := edit(t, explicit, "aws", "profile", `"default"`, false)
	text = edit(t, text, "aws", "allow_default_profile", "false", false)
	assertRefused(t, text, "aws.profile", "default")
	text = edit(t, explicit, "aws", "ami", "", true)
	text = edit(t, text, "aws", "arm_ami_ssm", "", true)
	assertRefused(t, text, "aws.ami", "")
	// Userinfo is forbidden even when there is no password to trigger the scan.
	value := "https://demo" + "@" + "example.org/SECRET-NEEDLE"
	assertRefused(t, edit(t, explicit, "aws", "my_address_url", strconv.Quote(value), false), "aws.my_address_url", "")
	account := "demo-account" + "@" + "example.org"
	assertRefused(t, edit(t, explicit, "gcp", "box_service_account", strconv.Quote(account), false), "gcp.box_service_account", account)
}

// TestAllowedChoices detects removing a supported enum or requiring both images.
func TestAllowedChoices(t *testing.T) {
	for _, row := range []struct{ table, key, values string }{
		{"defaults", "provider", "aws gcp"}, {"defaults", "arch", "x86 arm64 any"},
		{"gcp", "boot_disk_type", "pd-standard pd-balanced pd-ssd"},
		{"gcp.shape[0]", "arch", "x86 arm64"},
	} {
		for _, value := range strings.Fields(row.values) {
			t.Run(row.key+"-"+value, func(t *testing.T) {
				mustLoad(t, edit(t, explicit, row.table, row.key, strconv.Quote(value), false), testEnv(t))
			})
		}
	}
	text := edit(t, explicit, "aws", "profile", `"default"`, false)
	if got := mustLoad(t, text, testEnv(t)).AWS.Profile; got != "default" {
		t.Fatal("explicit permission did not allow the default profile")
	}
	for _, omitted := range []string{"ami", "arm_ami_ssm"} {
		mustLoad(t, edit(t, explicit, "aws", omitted, "", true), testEnv(t))
	}
}

// TestMissingRequired detects a required field becoming optional.
func TestMissingRequired(t *testing.T) {
	groups := []struct{ table, names string }{
		{"", "schema_version org"},
		{"aws", "profile region vpc security_group key_name ssh_identity"},
		{"gcp", "project region zones results_bucket box_service_account"},
		{"gcp.shape[0]", "type vcpu mem_gib price_usd_hour"},
	}
	for _, group := range groups {
		for _, key := range strings.Fields(group.names) {
			t.Run(fieldPath(group.table, key), func(t *testing.T) {
				assertRefused(t, edit(t, explicit, group.table, key, "", true), fieldPath(group.table, key), "")
			})
		}
	}
}

// TestWrongTypes detects coercion of scalars, tables or array items.
func TestWrongTypes(t *testing.T) {
	groups := []struct{ table, names, value string }{
		{"", "schema_version", "1.0"},
		{"", "org", "12"},
		{"ledger", "path schema registry", "12"},
		{"defaults", "provider arch name_prefix run_dir", "12"},
		{"defaults", "vcpu mem_gib root_gb idle_min hard_min", "1.0"},
		{"defaults", "cost_cap_usd disk_usd_gb_month", `"SECRET-NEEDLE"`},
		{"guest", "done_files busy_files", `"SECRET-NEEDLE"`},
		{"guest", "out_dir", "12"},
		{"aws", "profile region project_tag vpc security_group ami arm_ami_ssm key_name ssh_user ssh_identity my_address_url", "12"},
		{"aws", "families_x86 families_arm", `"SECRET-NEEDLE"`},
		{"aws", "max_candidates", "1.0"},
		{"aws", "ensure_ssh_ingress allow_default_profile allow_terminate", `"SECRET-NEEDLE"`},
		{"gcp", "project region network subnetwork box_service_account impersonate_service_account results_bucket object_prefix", "12"},
		{"gcp", "image_project image_family_x86 image_family_arm boot_disk_type gcloud_config_dir gcloud_configuration", "12"},
		{"gcp", "zones network_tags", `"SECRET-NEEDLE"`},
		{"gcp", "external_ip", `"SECRET-NEEDLE"`},
		{"gcp", "preemption_notice_sec", "1.0"},
		{"gcp.shape[0]", "type arch", "12"},
		{"gcp.shape[0]", "vcpu mem_gib", "1.0"},
		{"gcp.shape[0]", "price_usd_hour", `"SECRET-NEEDLE"`},
	}
	for _, group := range groups {
		for _, key := range strings.Fields(group.names) {
			t.Run(fieldPath(group.table, key), func(t *testing.T) {
				assertRefused(t, edit(t, explicit, group.table, key, group.value, false), fieldPath(group.table, key), group.value)
			})
		}
	}
	for _, row := range []struct{ table, key string }{
		{"guest", "done_files"}, {"guest", "busy_files"}, {"aws", "families_x86"},
		{"aws", "families_arm"}, {"gcp", "zones"}, {"gcp", "network_tags"},
	} {
		t.Run("item-"+row.key, func(t *testing.T) {
			assertRefused(t, edit(t, explicit, row.table, row.key, "[12]", false), fieldPath(row.table, row.key)+"[0]", "12")
		})
	}
	assertRefused(t, edit(t, explicit, "aws.subnets", "us-test-1a", "12", false), "aws.subnets.us-test-1a", "12")
	assertRefused(t, edit(t, explicit, "", "org", "2026-10-14T05:06:07Z", false), "org", "2026-10-14")
}

// TestNoCloudKeyFields detects a cloud credential field entering the schema.
func TestNoCloudKeyFields(t *testing.T) {
	for _, table := range []string{"aws", "gcp"} {
		for _, key := range []string{"key_file", "access_key", "secret", "password"} {
			t.Run(table+"-"+key, func(t *testing.T) {
				text := edit(t, explicit, table, key, `"SECRET-NEEDLE"`, false)
				path := writeConfig(t, text)
				_, err := boxcfg.Load(path, testEnv(t))
				want := path + ": " + table + "." + key + ": unknown key"
				if err == nil || err.Error() != want {
					t.Fatalf("cloud key field refusal = %v", err)
				}
			})
		}
	}
}
