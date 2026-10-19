package assembly

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
)

// Installation is administrator-owned service boot data, never a lane RPC or
// the lane-visible binding. It contains handles and immutable paths, no secrets.
type Installation struct {
	AdminEnrollment       *api.AdminEnrollmentEndpoint `json:"admin_enrollment,omitempty"`
	Binding               api.InstalledBinding         `json:"-"`
	Schema                string                       `json:"schema"`
	Config                string                       `json:"config"`
	ServiceUID            uint32                       `json:"service_uid"`
	ArtifactSHA256        api.Digest                   `json:"artifact_sha256"`
	BindingFile           string                       `json:"binding_file"`
	StateDirectory        string                       `json:"state_directory"`
	Socket                string                       `json:"socket"`
	SecretDirectory       string                       `json:"secret_directory"`
	SecretKeyHandle       api.ID                       `json:"secret_key_handle"`
	RuntimeManifest       api.BlobRef                  `json:"runtime_manifest"`
	LaunchEnrollment      *api.BlobRef                 `json:"launch_enrollment,omitempty"`
	Judge                 api.JudgeConfig              `json:"judge"`
	JudgeEndpoint         string                       `json:"judge_endpoint"`
	JudgeCredentialHandle api.ID                       `json:"judge_credential_handle,omitempty"`
	JudgeAlternative      *JudgeInstallation           `json:"judge_alternative,omitempty"`
	JudgeWorker           *JudgeWorkerInstallation     `json:"judge_worker,omitempty"`
	// Zero permits reads/startup only. It never authorizes positive-cost inference.
	PolicyMaxCostMicros int64 `json:"policy_max_cost_micros,omitempty"`
}

// These are enrolled deployment capabilities, never the active policy choice.
// EffectivePolicy.Judge selects provider/model/pins at Scope.PolicyGeneration.
type JudgeInstallation struct {
	Config           api.JudgeConfig          `json:"config"`
	Endpoint         string                   `json:"endpoint"`
	CredentialHandle api.ID                   `json:"credential_handle,omitempty"`
	Worker           *JudgeWorkerInstallation `json:"worker,omitempty"`
}

var installedConfigName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func loadInstallation(options Options) (Installation, error) {
	var installed Installation
	if !installedConfigName.MatchString(options.Config) {
		return installed, installError("invalid service configuration name")
	}
	if bound := os.Getenv("LANEBOSS_CONFIG"); bound != "" && bound != options.Config {
		return installed, &api.Error{Code: api.CodeConflict, Message: "service configuration conflicts with the active session binding", Instead: "Keep the current binding and use the separately installed service process."}
	}
	if options.InstallationFile == "" {
		return installed, &api.Error{Code: api.CodePrerequisite, Message: "administrator-installed service configuration is required", Instead: "Use serve --config NAME --installation FILE under the dedicated service UID after administrator setup."}
	}
	data, err := readProtected(options.InstallationFile, api.MaxFrameBytes)
	if err != nil {
		return installed, installedCheckFailure("service boot document", err)
	}
	if err := api.DecodeObject(data, &installed); err != nil {
		return installed, err
	}
	if err := validateInstallation(installed, options); err != nil {
		return installed, err
	}
	if os.Geteuid() == 0 || uint32(os.Geteuid()) != installed.ServiceUID {
		return installed, &api.Error{Code: api.CodeForbidden, Message: "serve requires its dedicated unprivileged service UID", Instead: "Start the administrator-installed service unit; never run the state owner as root or a lane UID."}
	}
	bindingBytes, err := readProtected(installed.BindingFile, api.MaxFrameBytes)
	if err != nil {
		return installed, installedCheckFailure("service endpoint binding", err)
	}
	if err := api.DecodeObject(bindingBytes, &installed.Binding); err != nil {
		return installed, err
	}
	if err := api.ValidateBinding(installed.Binding, installed.Config, release.Version); err != nil {
		return installed, err
	}
	if installed.Binding.ServiceUID != installed.ServiceUID || installed.Binding.Socket != installed.Socket || installed.Binding.ArtifactSHA256 != installed.ArtifactSHA256 {
		return installed, installError("service boot data differs from its protected endpoint binding")
	}
	for _, directory := range []string{installed.StateDirectory, installed.SecretDirectory, filepath.Dir(installed.Socket)} {
		if err := privateDirectory(directory, installed.ServiceUID); err != nil {
			return installed, installedCheckFailure("service private directory", err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return installed, installError("cannot resolve the running release artifact")
	}
	artifact, err := readProtected(executable, 256<<20)
	if err != nil {
		return installed, installedCheckFailure("running service artifact", err)
	}
	sum := sha256.Sum256(artifact)
	if api.Digest(hex.EncodeToString(sum[:])) != installed.ArtifactSHA256 {
		return installed, &api.Error{Code: api.CodeVersion, Message: "running artifact differs from the installed service generation", Instead: "Restore the coherent verified service/helper/client release."}
	}
	return installed, nil
}

func validateInstallation(installed Installation, options Options) error {
	if installed.PolicyMaxCostMicros < 0 || installed.PolicyMaxCostMicros > 1<<53-1 {
		return installError("invalid approved policy inference ceiling")
	}
	if installed.Schema != "laneboss.service-install.v2" || installed.Config != options.Config || installed.ServiceUID == 0 || !isDigest(installed.ArtifactSHA256) {
		return installError("invalid installed service generation or owner")
	}
	if endpoint := installed.AdminEnrollment; endpoint != nil {
		if err := api.ValidateAdminEnrollmentEndpoint(*endpoint); err != nil {
			return err
		}
		if endpoint.Config != installed.Config || endpoint.ServiceUID != installed.ServiceUID || endpoint.Socket == installed.Socket ||
			endpoint.Helper.SHA256 != installed.ArtifactSHA256 || endpoint.Helper.Version != release.Version {
			return installError("administrator enrollment needs its distinct protected service endpoint")
		}
	}
	if options.BindingFile != "" && options.BindingFile != installed.BindingFile {
		return &api.Error{Code: api.CodeConflict, Message: "supplied binding differs from the installed service binding", Instead: "Use the exact administrator-installed binding for this configuration."}
	}
	for _, path := range []string{installed.BindingFile, installed.StateDirectory, installed.Socket, installed.SecretDirectory} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return installError("installation paths must be absolute canonical protected paths")
		}
	}
	if overlap(installed.StateDirectory, installed.SecretDirectory) || overlap(installed.StateDirectory, filepath.Dir(installed.Socket)) || overlap(installed.SecretDirectory, filepath.Dir(installed.Socket)) {
		return installError("state, secret and runtime directories must be separate")
	}
	if installed.SecretKeyHandle == "" || installed.RuntimeManifest.ID == "" || !isDigest(installed.RuntimeManifest.SHA256) || installed.RuntimeManifest.Class != "manifest" || installed.RuntimeManifest.Bytes < 1 || installed.RuntimeManifest.Bytes > api.MaxObjectBytes {
		return installError("installation is missing protected key/runtime handles")
	}
	if ref := installed.LaunchEnrollment; ref != nil && (ref.ID == "" || !isDigest(ref.SHA256) || ref.Class != "manifest" || ref.Bytes < 1 || ref.Bytes > api.MaxObjectBytes) {
		return installError("invalid installed launch enrollment reference")
	}
	seen := make(map[string]bool)
	for _, enrollment := range judgeEnrollments(installed) {
		resolved, err := api.ResolveJudgeConfig(enrollment.Config)
		if err != nil {
			return installError(err.Error())
		}
		if seen[resolved.Provider] {
			return installError("judge endpoint enrollment repeats a provider")
		}
		seen[resolved.Provider] = true
		endpoint, err := url.Parse(enrollment.Endpoint)
		if err != nil || endpoint.Scheme != "http" && endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return installError("judge endpoint must be an enrolled HTTP endpoint without credentials")
		}
		if resolved.Provider == "typesafe" && enrollment.CredentialHandle == "" {
			return installError("TypeSafe endpoint requires its enrolled credential handle")
		}
		enrollment.Config = resolved
		if err := validateJudgeWorker(enrollment); err != nil {
			return err
		}
	}
	return nil
}

func readProtected(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, installError("protected input path must be absolute and canonical")
	}
	if err := protectedParents(filepath.Dir(path), 0); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > limit || !owned(before, 0) || before.Mode().Perm()&0022 != 0 {
		return nil, installError("installed input must be a bounded root-owned regular file without shared writes")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, installError("cannot open protected installed input")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, installError("installed input changed identity during open")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) != before.Size() || int64(len(data)) > limit {
		return nil, installError("installed input changed size or could not be read")
	}
	return data, nil
}

func privateDirectory(path string, serviceUID uint32) error {
	if err := protectedParents(filepath.Dir(path), serviceUID); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || !owned(info, serviceUID) || info.Mode().Perm()&0077 != 0 {
		return installError("service directory requires exclusive dedicated-UID ownership")
	}
	return nil
}

func protectedParents(path string, serviceUID uint32) error {
	for {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || !owned(info, 0) && !owned(info, serviceUID) || info.Mode().Perm()&0022 != 0 {
			return installError("installed path has a symlink, untrusted owner or shared-writable parent")
		}
		if path == "/" {
			return nil
		}
		path = filepath.Dir(path)
	}
}

func owned(info os.FileInfo, uid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid
}

func overlap(left, right string) bool {
	return left == right || strings.HasPrefix(left, right+string(filepath.Separator)) || strings.HasPrefix(right, left+string(filepath.Separator))
}

func isDigest(value api.Digest) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func installError(message string) *api.Error {
	return &api.Error{Code: api.CodePrerequisite, Message: message, Instead: "Repair the administrator-installed service generation before opening state or launching work."}
}

func installedCheckFailure(stage string, err error) error {
	if typed, ok := err.(*api.Error); ok {
		copy := *typed
		copy.Message = stage + ": " + copy.Message
		return &copy
	}
	return err
}
