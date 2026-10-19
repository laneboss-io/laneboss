package assembly

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

// This is credential-selection evidence, not provider authentication or a
// successful model request. Only the installed, rehashed CLI may supply it.
// The probe has a fresh private home and synthetic credentials, never a login.
type realCompatibility struct {
	mu        sync.Mutex
	installed Installation
	runtime   realRuntime
	measured  map[string]bool
}

func (p *realCompatibility) verify(ctx context.Context, wrapper, vendor api.Executable, mode string) (resultErr error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return runError(api.CodeCancelled, "compatibility measurement context ended")
	}
	if wrapper != p.runtime.Wrapper || vendor != p.runtime.Claude || wrapper.Version != claudock.ClaudockVersion || vendor.Version != claudock.ClaudeVersion || api.ClaudeSlotEnvironment(mode) == "" {
		return runError(api.CodeForbidden, "compatibility probe differs from the enrolled executable or credential mode")
	}
	current, err := loadRealRuntime(p.installed)
	if err != nil {
		return err
	}
	if current == nil || *current != p.runtime {
		return runError(api.CodeIntegrity, "compatibility probe executable enrollment changed")
	}
	if p.measured[mode] {
		return nil
	}
	home, err := os.MkdirTemp(p.installed.StateDirectory, ".credential-probe-")
	if err != nil {
		return runError(api.CodeUnavailable, "compatibility probe home cannot be created")
	}
	defer func() {
		if err := os.RemoveAll(home); err != nil {
			resultErr = errors.Join(resultErr, runError(api.CodeUnavailable, "compatibility probe home could not be collected"))
		}
	}()
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0700); err != nil {
		return runError(api.CodeUnavailable, "compatibility probe vendor home cannot be created")
	}
	probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	base := []string{"HOME=" + home, "PATH=/usr/bin:/bin", "LANG=C", "CLAUDE_CONFIG_DIR=" + filepath.Join(home, ".claude"),
		"DISABLE_AUTOUPDATER=1", "CLAUDE_CODE_DISABLE_" + "NONESSENTIAL_TRAFFIC=1"}
	version, err := compatibilityCommand(probeCtx, p.runtime.ClaudePath, base, "--version")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(version)), vendor.Version+" ") && strings.TrimSpace(string(version)) != vendor.Version {
		return runError(api.CodeVersion, "installed vendor declared a different version or its version probe failed")
	}
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return runError(api.CodeUnavailable, "compatibility probe could not generate synthetic input")
	}
	probeKey := "sk-ant-" + hex.EncodeToString(entropy[:])
	environment := append(append([]string{}, base...), api.ClaudeSlotEnvironment(mode)+"="+probeKey)
	clear(entropy[:])
	status, err := compatibilityCommand(probeCtx, p.runtime.ClaudePath, environment, "auth", "status", "--json")
	if err != nil || api.ValidateObjectJSON(status) != nil {
		return runError(api.CodeForbidden, "installed vendor did not report its selected credential mode")
	}
	if bytes.Contains(status, []byte(probeKey)) {
		return runError(api.CodeIntegrity, "compatibility probe output exposed its synthetic input")
	}
	var selection struct {
		LoggedIn    bool   `json:"loggedIn"`
		AuthMethod  string `json:"authMethod"`
		APIProvider string `json:"apiProvider"`
	}
	if json.Unmarshal(status, &selection) != nil || !selection.LoggedIn || selection.APIProvider != "firstParty" ||
		mode == "claude-api-key" && selection.AuthMethod != "api_key" || mode == "claudock-headless" && selection.AuthMethod != "oauth_token" {
		return runError(api.CodeForbidden, "installed vendor selected another credential method or provider")
	}
	// Hash again after execution; a successful old process cannot attest new
	// bytes installed at the same name while the probe was running.
	current, err = loadRealRuntime(p.installed)
	if err != nil {
		return err
	}
	if current == nil || *current != p.runtime {
		return runError(api.CodeIntegrity, "compatibility probe executable changed during measurement")
	}
	if err := p.retain(mode, version, status); err != nil {
		return err
	}
	if p.measured == nil {
		p.measured = make(map[string]bool)
	}
	p.measured[mode] = true
	return nil
}

type compatibilityMeasurement struct {
	Schema           string         `json:"schema"`
	Wrapper          api.Executable `json:"wrapper"`
	Vendor           api.Executable `json:"vendor"`
	Mode             string         `json:"mode"`
	Adapter          string         `json:"adapter"`
	VersionOutput    string         `json:"version_output"`
	CredentialStatus []byte         `json:"credential_status"`
}

func (p *realCompatibility) retain(mode string, version, status []byte) error {
	directory := filepath.Join(p.installed.StateDirectory, "claudock-compatibility")
	if err := os.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return runError(api.CodeUnavailable, "compatibility evidence directory cannot be created")
	}
	if err := privateDirectory(directory, p.installed.ServiceUID); err != nil {
		return err
	}
	data, err := json.Marshal(compatibilityMeasurement{Schema: "laneboss.claudock-compatibility.v1", Wrapper: p.runtime.Wrapper, Vendor: p.runtime.Claude,
		Mode: mode, Adapter: claudock.AdapterVersion, VersionOutput: string(version), CredentialStatus: append([]byte{}, status...)})
	if err != nil {
		return runError(api.CodeIntegrity, "compatibility measurement cannot be encoded")
	}
	file, err := os.CreateTemp(directory, "measurement-")
	if err != nil {
		return runError(api.CodeUnavailable, "compatibility measurement cannot be retained")
	}
	n, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || n != len(data) || syncErr != nil || closeErr != nil {
		return runError(api.CodeIntegrity, "compatibility measurement was not durably retained")
	}
	parent, err := os.Open(directory)
	if err != nil {
		return runError(api.CodeIntegrity, "compatibility evidence directory cannot be synchronized")
	}
	if err := errors.Join(parent.Sync(), parent.Close()); err != nil {
		return runError(api.CodeIntegrity, "compatibility evidence directory was not synchronized")
	}
	return nil
}

type compatibilityOutput struct {
	bytes.Buffer
	exceeded bool
}

func (b *compatibilityOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 64<<10 {
		b.exceeded = true
		return 0, errors.New("bounded compatibility output exceeded")
	}
	return b.Buffer.Write(data)
}

func compatibilityCommand(ctx context.Context, binary string, environment []string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env, cmd.Dir = environment, "/"
	var output compatibilityOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil || output.exceeded {
		return nil, runError(api.CodeForbidden, "installed compatibility command failed")
	}
	return append([]byte{}, output.Bytes()...), nil
}
