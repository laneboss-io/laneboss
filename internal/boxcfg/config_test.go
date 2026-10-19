package boxcfg_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcfg"
	"laneboss.io/laneboss/internal/boxcore"
)

const minimal = "schema_version = 1\norg = \"example-org\"\n"

const awsSmall = `[aws]
profile = "demo-profile"
region = "us-test-1"
vpc = "vpc-0abc1234"
security_group = "sg-0abc1234"
ami = "ami-0abc1234"
key_name = "demo-key"
ssh_identity = "~/.ssh/demo-key"
`

const gcpSmall = `[gcp]
project = "demo-project"
region = "demo-east1"
zones = ["demo-east1-a"]
results_bucket = "demo-bucket"
box_service_account = "demo-account"
[[gcp.shape]]
type = "demo-small"
vcpu = 2
mem_gib = 4
price_usd_hour = 0.04
`

const explicit = `schema_version = 1
org = "example-org"
[ledger]
path = "~/events.jsonl"
schema = "demo-event/v2"
registry = "~/registry.json"
[defaults]
provider = "gcp"
vcpu = 8
mem_gib = 24
arch = "arm64"
root_gb = 80
idle_min = 20
hard_min = 240
cost_cap_usd = 9.5
disk_usd_gb_month = 0.25
name_prefix = "demo-"
run_dir = "~/runs"
[guest]
done_files = ["/tmp/demo-done", "/tmp/demo-done2"]
busy_files = ["/tmp/demo-busy", "/tmp/demo-busy2"]
out_dir = "/tmp/demo-out"
[aws]
profile = "demo-profile"
region = "us-test-1"
project_tag = "demo tag"
vpc = "vpc-0abc1234"
security_group = "sg-0abc1234"
ami = "ami-0abc1234"
arm_ami_ssm = "/demo/image"
key_name = "demo key"
ssh_user = "demo_user"
ssh_identity = "~/.ssh/demo-key"
families_x86 = ["c5a", "m7i"]
families_arm = ["c7g"]
max_candidates = 7
ensure_ssh_ingress = true
my_address_url = "https://example.org/address"
allow_default_profile = true
allow_terminate = true
[aws.subnets]
us-test-1a = "subnet-0abc1234"
[gcp]
project = "demo-project"
region = "demo-east1"
zones = ["demo-east1-a", "demo-east1-b"]
network = "demo-net"
subnetwork = "demo-subnet"
external_ip = false
network_tags = ["demo-ssh", "demo-box"]
box_service_account = "demo-account"
impersonate_service_account = "demo-other"
results_bucket = "demo-bucket"
object_prefix = "demo/runs"
image_project = "demo-images"
image_family_x86 = "demo-x86"
image_family_arm = "demo-arm"
boot_disk_type = "pd-ssd"
preemption_notice_sec = 120
gcloud_config_dir = "~/cloud"
gcloud_configuration = "demo_config"
[[gcp.shape]]
type = "demo-small"
vcpu = 2
mem_gib = 4
arch = "x86"
price_usd_hour = 0.0321
[[gcp.shape]]
type = "demo-large"
vcpu = 8
mem_gib = 16
arch = "arm64"
price_usd_hour = 0.12
`

func testEnv(t *testing.T) boxcfg.Env {
	t.Helper()
	root := t.TempDir()
	return boxcfg.Env{
		Home: filepath.Join(root, "config"), StateHome: filepath.Join(root, "state"),
		UserHome: filepath.Join(root, "user"),
	}
}

func writeConfig(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "box.toml")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustLoad(t *testing.T, text string, env boxcfg.Env) *boxcore.Config {
	t.Helper()
	c, err := boxcfg.Load(writeConfig(t, text), env)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestLoadExplicit checks every field against an independent expected configuration.
func TestLoadExplicit(t *testing.T) {
	env := testEnv(t)
	path := writeConfig(t, explicit)
	got, err := boxcfg.Load(path, env)
	if err != nil {
		t.Fatal(err)
	}
	home := env.UserHome
	want := &boxcore.Config{
		Path: path, Org: "example-org",
		Ledger: boxcore.LedgerConfig{
			Path: filepath.Join(home, "events.jsonl"), Schema: "demo-event/v2",
			Registry: filepath.Join(home, "registry.json"),
		},
		Defaults: boxcore.Defaults{
			Provider: "gcp", VCPU: 8, MemGiB: 24, Arch: "arm64", RootGB: 80,
			IdleMin: 20, HardMin: 240, CostCapUSD: 9.5, DiskUSDGBMonth: 0.25,
			NamePrefix: "demo-", RunDir: filepath.Join(home, "runs"),
		},
		Guest: boxcore.GuestConfig{
			DoneFiles: []string{"/tmp/demo-done", "/tmp/demo-done2"},
			BusyFiles: []string{"/tmp/demo-busy", "/tmp/demo-busy2"}, OutDir: "/tmp/demo-out",
		},
		AWS: &boxcore.AWSConfig{
			Profile: "demo-profile", Region: "us-test-1", ProjectTag: "demo tag",
			VPC: "vpc-0abc1234", SecurityGroup: "sg-0abc1234", AMI: "ami-0abc1234",
			ArmAMISSM: "/demo/image", KeyName: "demo key", SSHUser: "demo_user",
			SSHIdentity: filepath.Join(home, ".ssh", "demo-key"),
			FamiliesX86: []string{"c5a", "m7i"}, FamiliesArm: []string{"c7g"},
			MaxCandidates: 7, Subnets: map[string]string{"us-test-1a": "subnet-0abc1234"},
			EnsureSSHIngress: true, MyAddressURL: "https://example.org/address",
			AllowDefaultProfile: true, AllowTerminate: true,
		},
		GCP: &boxcore.GCPConfig{
			Project: "demo-project", Region: "demo-east1", Zones: []string{"demo-east1-a", "demo-east1-b"},
			Network: "demo-net", Subnetwork: "demo-subnet", ExternalIP: false,
			NetworkTags: []string{"demo-ssh", "demo-box"}, BoxServiceAccount: "demo-account",
			ImpersonateServiceAccount: "demo-other", ResultsBucket: "demo-bucket", ObjectPrefix: "demo/runs",
			ImageProject: "demo-images", ImageFamilyX86: "demo-x86", ImageFamilyArm: "demo-arm",
			BootDiskType: "pd-ssd", PreemptionNoticeSec: 120, GcloudConfigDir: filepath.Join(home, "cloud"),
			GcloudConfiguration: "demo_config",
			Shapes: []boxcore.GCPShape{
				{Type: "demo-small", VCPU: 2, MemGiB: 4, Arch: "x86", PriceUSDHour: 0.0321},
				{Type: "demo-large", VCPU: 8, MemGiB: 16, Arch: "arm64", PriceUSDHour: 0.12},
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded configuration differs:\ngot %#v\nwant %#v", got, want)
	}
	for _, dir := range []string{env.Home, env.StateHome, env.UserHome} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("Load created a directory or stat failed: %v", err)
		}
	}
}

// TestLoadDefaults detects omitted defaults and storage shared between loads.
func TestLoadDefaults(t *testing.T) {
	env := testEnv(t)
	got := mustLoad(t, minimal, env)
	want := &boxcore.Config{
		Path: got.Path, Org: "example-org",
		Ledger: boxcore.LedgerConfig{
			Path: filepath.Join(env.StateHome, "boxes", "ledger.jsonl"), Schema: "laneboss-box-event/v1",
		},
		Defaults: boxcore.Defaults{
			VCPU: 2, MemGiB: 4, Arch: "any", RootGB: 150, IdleMin: 30, HardMin: 360,
			CostCapUSD: 5, DiskUSDGBMonth: 0.10, NamePrefix: "lb-",
			RunDir: filepath.Join(env.StateHome, "boxes", "runs"),
		},
		Guest: boxcore.GuestConfig{
			DoneFiles: []string{"/var/tmp/lb-done"}, BusyFiles: []string{"/var/tmp/lb-busy"}, OutDir: "/var/lib/lb-box/out",
		},
	}
	if !reflect.DeepEqual(got, want) || !filepath.IsAbs(got.Path) {
		t.Fatalf("minimal defaults differ: %#v", got)
	}
	got = mustLoad(t, minimal+awsSmall+gcpSmall, env)
	want.Path = got.Path
	want.AWS = &boxcore.AWSConfig{
		Profile: "demo-profile", Region: "us-test-1", ProjectTag: "example-org",
		VPC: "vpc-0abc1234", SecurityGroup: "sg-0abc1234", AMI: "ami-0abc1234",
		KeyName: "demo-key", SSHUser: "ubuntu", SSHIdentity: filepath.Join(env.UserHome, ".ssh", "demo-key"),
		FamiliesX86: []string{"c5", "c5a", "c6i", "c6a", "c7i", "c7a", "m5", "m6i", "m6a", "m7i", "m7a"},
		FamiliesArm: []string{"c6g", "c7g", "m6g", "m7g"}, MaxCandidates: 3,
		Subnets: map[string]string{}, MyAddressURL: "https://checkip.amazonaws.com",
	}
	want.GCP = &boxcore.GCPConfig{
		Project: "demo-project", Region: "demo-east1", Zones: []string{"demo-east1-a"},
		ExternalIP: true, NetworkTags: []string{}, BoxServiceAccount: "demo-account",
		ResultsBucket: "demo-bucket", ObjectPrefix: "runs", ImageProject: "ubuntu-os-cloud",
		ImageFamilyX86: "ubuntu-2404-lts-amd64", ImageFamilyArm: "ubuntu-2404-lts-arm64", BootDiskType: "pd-balanced",
		Shapes: []boxcore.GCPShape{{Type: "demo-small", VCPU: 2, MemGiB: 4, Arch: "x86", PriceUSDHour: 0.04}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("provider defaults differ:\ngot %#v\nwant %#v", got, want)
	}
	got.AWS.FamiliesX86[0] = "demo"
	got.Guest.DoneFiles[0] = "/tmp/demo"
	again := mustLoad(t, minimal+awsSmall+gcpSmall, env)
	if !reflect.DeepEqual(again.AWS, want.AWS) || !reflect.DeepEqual(again.Guest, want.Guest) {
		t.Fatal("defaults share mutable storage across loads")
	}
}

// TestLoadPresentZero detects defaults overwriting explicitly present zero values.
func TestLoadPresentZero(t *testing.T) {
	env := testEnv(t)
	text := minimal + `[ledger]
registry = ""
[defaults]
mem_gib = 0
disk_usd_gb_month = 0
` + awsSmall + `families_x86 = []
families_arm = []
ensure_ssh_ingress = false
allow_default_profile = false
allow_terminate = false
` + strings.Replace(gcpSmall, "[[gcp.shape]]", `external_ip = false
network_tags = []
impersonate_service_account = ""
gcloud_config_dir = ""
gcloud_configuration = ""
[[gcp.shape]]`, 1)
	got := mustLoad(t, text, env)
	if got.Defaults.MemGiB != 0 || got.Defaults.DiskUSDGBMonth != 0 || got.GCP.ExternalIP ||
		len(got.AWS.FamiliesX86) != 0 || len(got.AWS.FamiliesArm) != 0 || len(got.GCP.NetworkTags) != 0 ||
		got.Ledger.Registry != "" || got.GCP.ImpersonateServiceAccount != "" ||
		got.GCP.GcloudConfigDir != "" || got.GCP.GcloudConfiguration != "" ||
		got.AWS.EnsureSSHIngress || got.AWS.AllowDefaultProfile || got.AWS.AllowTerminate {
		t.Fatal("an explicit zero, empty value or false was replaced")
	}
}
