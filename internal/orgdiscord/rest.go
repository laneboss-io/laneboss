package orgdiscord

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/testenv"
)

const testBaseEnv = "LANEBOSS_TEST_DISCORD_BASE_URL"

type discordSettings struct{ guild, owner, secret string }
type secretStore struct{ kind, path, service string }

func settings(files *orgFiles) (discordSettings, secretStore, error) {
	var discord discordSettings
	var store secretStore
	config, err := files.toml(".laneboss/org.toml", "org.toml")
	if err != nil {
		return discord, store, err
	}
	services, _ := config["services"].(map[string]any)
	entry, ok := services["discord"].(map[string]any)
	if !ok {
		return discord, store, refused("org.toml requires a services.discord table")
	}
	discord.guild, err = checkedString(entry["guild_id"], "org.toml services.discord.guild_id", idPattern)
	if err != nil {
		return discord, store, err
	}
	discord.secret, ok = entry["token_secret"].(string)
	if !ok || !secretPattern.MatchString(discord.secret) {
		return discord, store, refused("org.toml services.discord.token_secret must name a secret, never contain its value")
	}
	if owner, exists := entry["owner_id"]; exists {
		discord.owner, err = checkedString(owner, "org.toml services.discord.owner_id", idPattern)
		if err != nil {
			return discord, store, err
		}
	}
	storage, ok := config["secret_store"].(map[string]any)
	if !ok {
		return discord, store, refused("org.toml secret_store.kind must be file or keychain")
	}
	store.kind, _ = storage["kind"].(string)
	switch store.kind {
	case "file":
		location, ok := storage["path"].(string)
		if !ok {
			return discord, store, refused("secret_store.path must be an absolute path outside the org")
		}
		store.path, err = expandHome(location)
		if err != nil {
			return discord, store, err
		}
		if !filepath.IsAbs(store.path) {
			return discord, store, refused("secret_store.path must be an absolute path outside the org")
		}
		// Resolve existing ancestors even for a missing file: dry-run validates
		// the location without opening or requiring the secret store.
		resolved, err := resolvedLocation(store.path)
		if err != nil {
			return discord, store, err
		}
		relative, err := filepath.Rel(files.path, resolved)
		if err != nil || relative == "." || filepath.IsLocal(relative) {
			return discord, store, refused("the org secret store must be outside the org and must not be a symbolic link")
		}
		rootInfo, err := files.root.Stat(".")
		if err != nil {
			return discord, store, refused("cannot inspect the org secret store location")
		}
		if info, err := os.Lstat(store.path); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return discord, store, refused("the org secret store must be outside the org and must not be a symbolic link")
		}
		for parent := filepath.Dir(resolved); ; parent = filepath.Dir(parent) {
			info, err := os.Stat(parent)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return discord, store, refused("cannot inspect the org secret store location")
			}
			if err == nil && os.SameFile(info, rootInfo) {
				return discord, store, refused("the org secret store must be outside the org and must not be a symbolic link")
			}
			if _, err := os.Lstat(filepath.Join(parent, ".git")); err == nil {
				return discord, store, refused("the org secret store must be outside every repository")
			} else if !errors.Is(err, os.ErrNotExist) {
				return discord, store, refused("cannot inspect the org secret store repository location")
			}
			if parent == filepath.Dir(parent) {
				break
			}
		}
	case "keychain":
		store.service, err = checkedString(storage["service"], "org.toml secret_store.service", namePattern)
		if err != nil {
			return discord, store, err
		}
	default:
		return discord, store, refused("org.toml secret_store.kind must be file or keychain")
	}
	return discord, store, nil
}

func resolvedLocation(path string) (string, error) {
	current := filepath.Clean(path)
	var remainder []string
	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", refused("cannot inspect the org secret store location")
			}
			for i := len(remainder) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, remainder[i])
			}
			return resolved, nil
		} else if !os.IsNotExist(err) {
			return "", refused("cannot inspect the org secret store location")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", refused("cannot inspect the org secret store location")
		}
		remainder = append(remainder, filepath.Base(current))
		current = parent
	}
}

func loadToken(discord discordSettings, store secretStore) (string, error) {
	var value any
	if store.kind == "file" {
		handle, err := os.OpenFile(store.path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return "", refused("cannot read org secret store")
		}
		defer handle.Close()
		data, err := readHandle(handle, "org secret store", true)
		if err != nil {
			return "", err
		}
		secrets, err := parseTOML(data, "org secret store")
		if err != nil {
			return "", err
		}
		value = secrets[discord.secret]
	} else {
		if runtime.GOOS != "darwin" {
			return "", refused("the keychain secret store requires macOS; use a private file store on this platform")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// The security tool receives only the service and secret names. Its
		// stdout is captured in memory; neither stdout nor diagnostics are logged.
		data, err := exec.CommandContext(ctx, "/usr/bin/security", "find-generic-password", "-s", store.service, "-a", discord.secret, "-w").Output()
		if err != nil {
			return "", refused("cannot resolve the named bot secret from the org keychain")
		}
		if !utf8.Valid(data) {
			return "", refused("the named bot secret must be UTF-8 text")
		}
		value = strings.TrimSpace(string(data))
	}
	token, ok := value.(string)
	if !ok || !tokenPattern.MatchString(token) {
		return "", refused("the named bot secret is missing or is not a valid bot token")
	}
	return token, nil
}

func apiBase() (string, error) {
	base, set := testenv.DiscordBase()
	if !set {
		return "https://discord.com/api/v10", nil
	}
	u, err := url.Parse(base)
	valid := err == nil
	if valid {
		ip := net.ParseIP(u.Hostname())
		port, portErr := strconv.Atoi(u.Port())
		valid = u.Scheme == "http" && ip != nil && ip.IsLoopback() && portErr == nil && port > 0 && port <= 65535 &&
			u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" &&
			!strings.Contains(base, "#") && strings.TrimRight(u.Path, "/") == "/api/v10" && u.RawPath == "" && u.Opaque == ""
	}
	if !valid {
		return "", refused(testBaseEnv + " is for a localhost HTTP test stub at /api/v10 only")
	}
	return strings.TrimRight(base, "/"), nil
}

type discordREST struct {
	token, base string
	client      *http.Client
}

func newREST(token string) (*discordREST, error) {
	base, err := apiBase()
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 20 * time.Second}).DialContext,
		TLSHandshakeTimeout: 20 * time.Second, ResponseHeaderTimeout: 20 * time.Second, MaxResponseHeaderBytes: maxBytes}
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &discordREST{token, base, client}, nil
}

func (api *discordREST) request(method, path string, body any, creating bool) (map[string]any, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, refused("Discord REST request body is invalid")
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, api.base+path, reader)
	if err != nil {
		return nil, refused("Discord REST request could not be completed")
	}
	req.Header.Set("Authorization", "Bot "+api.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "DiscordBot (laneboss, 1.0)")
	response, err := api.client.Do(req)
	if err != nil {
		return nil, refused("Discord REST request could not be completed")
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return nil, refused("Discord REST redirects are refused; no bot credential was forwarded")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if creating && response.StatusCode == 403 {
			return nil, refused("Discord refused channel creation (HTTP 403): the bot needs Manage Channels. Owner step: in Discord, Server Settings > Roles > the bot's role, enable Manage Channels (only that permission). Or create the channel yourself and rerun with --channel-id")
		}
		return nil, refused(fmt.Sprintf("Discord REST request failed (HTTP %d)", response.StatusCode))
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return nil, refused("Discord REST request could not be completed")
	}
	if len(raw) > maxBytes {
		return nil, refused("Discord REST response exceeds 1 MiB")
	}
	value, err := parseJSON(raw, "Discord REST response")
	if err != nil {
		return nil, err
	}
	reply, ok := value.(map[string]any)
	if !ok {
		return nil, refused("Discord REST response must be an object")
	}
	return reply, nil
}
