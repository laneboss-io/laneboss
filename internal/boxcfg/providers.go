package boxcfg

import (
	"fmt"
	"net/url"
	"strings"

	"laneboss.io/laneboss/internal/boxcore"
)

func addressURL(text string) bool {
	if !boundedText(text, 1, 200) || strings.ContainsRune(text, ' ') {
		return false
	}
	u, err := url.Parse(text)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Opaque == ""
}

func loadAWS(s section, org string) *boxcore.AWSConfig {
	s.allowed("profile region project_tag vpc security_group ami arm_ami_ssm " +
		"key_name ssh_user ssh_identity families_x86 families_arm max_candidates " +
		"subnets ensure_ssh_ingress my_address_url allow_default_profile allow_terminate")
	a := &boxcore.AWSConfig{
		Profile:       s.text("profile", "", true, grammar(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`)),
		Region:        s.text("region", "", true, grammar(`[a-z]{2,4}(-[a-z0-9]+)+-[0-9]+`)),
		ProjectTag:    s.text("project_tag", org, false, boxcore.TagSafe),
		VPC:           s.text("vpc", "", true, grammar(`vpc-[0-9a-f]{8,17}`)),
		SecurityGroup: s.text("security_group", "", true, grammar(`sg-[0-9a-f]{8,17}`)),
		AMI:           s.text("ami", "", false, grammar(`ami-[0-9a-f]{8,17}`)),
		ArmAMISSM: s.text("arm_ami_ssm", "", false, func(text string) bool {
			return boundedText(text, 1, 256) && strings.HasPrefix(text, "/") && !strings.ContainsRune(text, ' ')
		}),
		KeyName:             s.text("key_name", "", true, grammar(`[A-Za-z0-9][A-Za-z0-9._ -]{0,254}`)),
		SSHUser:             s.text("ssh_user", "ubuntu", false, grammar(`[a-z_][a-z0-9_-]{0,31}`)),
		SSHIdentity:         s.path("ssh_identity", "", true, false),
		FamiliesX86:         s.texts("families_x86", strings.Fields("c5 c5a c6i c6a c7i c7a m5 m6i m6a m7i m7a"), false, 0, -1, grammar(`[a-z][a-z0-9]{1,5}`)),
		FamiliesArm:         s.texts("families_arm", strings.Fields("c6g c7g m6g m7g"), false, 0, -1, grammar(`[a-z][a-z0-9]{1,5}`)),
		MaxCandidates:       s.integer("max_candidates", 3, false, 1, 10),
		Subnets:             make(map[string]string),
		EnsureSSHIngress:    s.boolean("ensure_ssh_ingress", false),
		MyAddressURL:        s.text("my_address_url", "https://checkip.amazonaws.com", false, addressURL),
		AllowDefaultProfile: s.boolean("allow_default_profile", false),
		AllowTerminate:      s.boolean("allow_terminate", false),
	}
	if a.AMI == "" && a.ArmAMISSM == "" {
		s.v.fail(s.key("ami"), "an image or image parameter is required")
	}
	if a.Profile == "default" && !a.AllowDefaultProfile {
		s.v.fail(s.key("profile"), "requires explicit permission for the reserved profile")
	}
	subnets := s.child("subnets")
	zone := grammar(`[a-z]{2,4}(-[a-z0-9]+)+-[0-9]+[a-z]`)
	for _, key := range keys(subnets.data) {
		if !zone(key) {
			s.v.fail(subnets.prefix, "zone keys must match the required grammar")
		}
		a.Subnets[key] = subnets.text(key, "", true, grammar(`subnet-[0-9a-f]{8,17}`))
	}
	return a
}

func loadGCP(s section) *boxcore.GCPConfig {
	s.allowed("project region zones network subnetwork external_ip network_tags " +
		"box_service_account impersonate_service_account results_bucket object_prefix " +
		"image_project image_family_x86 image_family_arm boot_disk_type " +
		"preemption_notice_sec gcloud_config_dir gcloud_configuration shape")
	project := grammar(`[a-z][a-z0-9-]{4,28}[a-z0-9]`)
	network := grammar(`[a-z]([-a-z0-9]{0,61}[a-z0-9])?`)
	image := grammar(`[a-z][a-z0-9-]{1,62}`)
	g := &boxcore.GCPConfig{
		Project:                   s.text("project", "", true, project),
		Region:                    s.text("region", "", true, grammar(`[a-z]+-[a-z]+[0-9]+`)),
		Network:                   s.text("network", "", false, network),
		Subnetwork:                s.text("subnetwork", "", false, network),
		ExternalIP:                s.boolean("external_ip", true),
		NetworkTags:               s.texts("network_tags", []string{}, false, 0, 8, network),
		BoxServiceAccount:         s.text("box_service_account", "", true, project),
		ImpersonateServiceAccount: s.text("impersonate_service_account", "", false, optional(project)),
		ResultsBucket:             s.text("results_bucket", "", true, grammar(`[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]`)),
		ObjectPrefix: s.text("object_prefix", "runs", false,
			grammar(`[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*`)),
		ImageProject:        s.text("image_project", "ubuntu-os-cloud", false, project),
		ImageFamilyX86:      s.text("image_family_x86", "ubuntu-2404-lts-amd64", false, image),
		ImageFamilyArm:      s.text("image_family_arm", "ubuntu-2404-lts-arm64", false, image),
		BootDiskType:        s.text("boot_disk_type", "pd-balanced", false, choice("pd-standard", "pd-balanced", "pd-ssd")),
		PreemptionNoticeSec: s.integer("preemption_notice_sec", 0, false, 0, 120),
		GcloudConfigDir:     s.path("gcloud_config_dir", "", false, true),
		GcloudConfiguration: s.text("gcloud_configuration", "", false, optional(grammar(`[a-z][a-z0-9_-]{0,62}`))),
	}
	g.Zones = s.texts("zones", nil, true, 1, 8, func(zone string) bool {
		prefix := g.Region + "-"
		return strings.HasPrefix(zone, prefix) && len(zone) == len(prefix)+1 &&
			zone[len(prefix)] >= 'a' && zone[len(prefix)] <= 'z'
	})
	if g.PreemptionNoticeSec != 0 && g.PreemptionNoticeSec != 120 {
		s.v.fail(s.key("preemption_notice_sec"), "must be an allowed notice duration")
	}
	value, present := s.data["shape"]
	if !present {
		s.v.fail(s.key("shape"), "at least one shape is required")
		return g
	}
	rows, ok := array(value)
	if !ok || len(rows) == 0 {
		s.v.fail(s.key("shape"), "must be a non-empty array of tables")
		return g
	}
	g.Shapes = make([]boxcore.GCPShape, len(rows))
	for i, value := range rows {
		row := section{v: s.v, prefix: fmt.Sprintf("%s[%d]", s.key("shape"), i)}
		var table bool
		row.data, table = value.(map[string]any)
		if !table {
			s.v.fail(row.prefix, "must be a table")
		}
		row.allowed("type vcpu mem_gib arch price_usd_hour")
		g.Shapes[i] = boxcore.GCPShape{
			Type:         row.text("type", "", true, grammar(`[a-z][a-z0-9-]{1,40}`)),
			VCPU:         row.integer("vcpu", 0, true, 1, 416),
			MemGiB:       row.integer("mem_gib", 0, true, 1, 11776),
			Arch:         row.text("arch", "x86", false, choice("x86", "arm64")),
			PriceUSDHour: row.number("price_usd_hour", 0, true, 0, 1000, true),
		}
	}
	return g
}
