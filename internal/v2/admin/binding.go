package admin

import (
	"path/filepath"
	"runtime"
	"strings"

	"laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
)

const (
	adminSchema    = "laneboss.admin.v2"
	helperProtocol = "laneboss.helper.v2"
)

// installation is administrator-owned local configuration, not a public RPC
// or a substitute for the service/identity lane's endpoint binding.
type installation struct {
	Schema     string              `json:"schema"`
	Revision   string              `json:"contract_revision"`
	Config     string              `json:"config"`
	Generation api.Generation      `json:"generation"`
	Release    api.ReleaseManifest `json:"release"`
	Artifact   api.ReleaseArtifact `json:"artifact"`
	Service    account             `json:"service"`
	Lanes      []account           `json:"lanes"`
}

type account struct {
	Name string `json:"name"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
}

func bindingPath(config string) string {
	return filepath.Join("/etc/laneboss-v2/admin", config+".json")
}

// Installed canaries use the same instance selected by the fixed helper unit.
// Neither a guessed configuration nor a caller-supplied file selects a release.
func helperControlConfig(membership string) (string, error) {
	unit, ok := strings.CutPrefix(membership, "/system.slice/laneboss-helper@")
	if !ok {
		return "", failure(api.CodePrerequisite, "installed canary requires its fixed helper control unit")
	}
	config, ok := strings.CutSuffix(unit, ".service/control")
	if !ok || !validConfig(config) {
		return "", failure(api.CodePrerequisite, "installed canary requires its fixed helper control unit")
	}
	return config, nil
}
func (b installation) binaryPath() string {
	return filepath.Join("/usr/lib/laneboss-v2", b.Release.Version, "laneboss")
}
func (b installation) runtimePath() string {
	return filepath.Join("/run/laneboss-v2", b.Config)
}
func (b installation) socketPath() string { return filepath.Join(b.runtimePath(), "helper.sock") }
func (b installation) statePath() string {
	return filepath.Join("/var/lib/laneboss-v2/helper", b.Config)
}
func (b installation) cgroupPath() string {
	return filepath.Join("/sys/fs/cgroup/system.slice", "laneboss-helper@"+b.Config+".service", "lanes")
}

func (b installation) validate() error {
	if b.Schema != adminSchema || !validConfig(b.Config) || b.Generation == 0 || b.Generation > 1<<53-1 {
		return failure(api.CodeInvalid, "invalid installed helper configuration")
	}
	r := b.Release
	if b.Revision != api.ContractRevision || r.Protocol != api.Protocol || r.Schema != api.SchemaVersion || !versionPattern.MatchString(r.Version) || r.Version != identity.Version {
		return failure(api.CodeVersion, "helper release protocol, schema or version mismatch")
	}
	if !validDigest(r.SourceSHA256) || !validID(r.VendorManifest.ID) ||
		!validDigest(r.VendorManifest.SHA256) || r.VendorManifest.Bytes <= 0 ||
		r.VendorManifest.Bytes > api.MaxObjectBytes || r.VendorManifest.Class == "" || len(r.Artifacts) == 0 || len(r.Artifacts) > 32 {
		return failure(api.CodeIntegrity, "incomplete installed release manifest")
	}
	seen := map[string]bool{}
	matches := 0
	for _, artifact := range r.Artifacts {
		key := artifact.OS + "/" + artifact.Arch
		if (artifact.OS != "linux" && artifact.OS != "darwin") ||
			(artifact.Arch != "amd64" && artifact.Arch != "arm64") ||
			seen[key] || !validDigest(artifact.SHA256) || artifact.Bytes <= 0 || artifact.Bytes > 1<<30 {
			return failure(api.CodeIntegrity, "invalid or duplicate release artifact")
		}
		seen[key] = true
		if artifact == b.Artifact {
			matches++
		}
	}
	if matches != 1 || b.Artifact.OS != "linux" || b.Artifact.Arch != runtime.GOARCH {
		return failure(api.CodeVersion, "helper artifact does not match the release platform")
	}
	if b.Service.UID == 0 || b.Service.GID == 0 || !validID(api.ID(b.Service.Name)) ||
		len(b.Lanes) == 0 || len(b.Lanes) > 256 {
		return failure(api.CodeIntegrity, "invalid installed service account or lane pool")
	}
	uids := map[uint32]bool{0: true, b.Service.UID: true}
	gids := map[uint32]bool{0: true, b.Service.GID: true}
	names := map[string]bool{b.Service.Name: true}
	for _, lane := range b.Lanes {
		if uids[lane.UID] || gids[lane.GID] || names[lane.Name] || !validID(api.ID(lane.Name)) {
			return failure(api.CodeIntegrity, "lane accounts must have distinct nonservice UIDs and groups")
		}
		uids[lane.UID], gids[lane.GID], names[lane.Name] = true, true, true
	}
	return nil
}

func validateLease(lease api.HelperLease, b installation) error {
	if !validID(lease.ID) || !validID(lease.ContainmentID) || lease.EndpointGeneration != b.Generation {
		return failure(api.CodeIntegrity, "helper returned an invalid lease binding")
	}
	for _, lane := range b.Lanes {
		if lease.UID == lane.UID && lease.GID == lane.GID {
			return nil
		}
	}
	return failure(api.CodeIntegrity, "helper returned an account outside its installed pool")
}
