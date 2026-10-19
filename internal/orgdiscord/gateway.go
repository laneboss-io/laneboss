package orgdiscord

import (
	"fmt"
	"io"
	"path/filepath"

	"laneboss.io/laneboss/internal/cliargs"
)

// GatewayConfig exports validated, names-only settings. It neither opens the
// secret store nor contacts Discord, and resolves all paths for its consumer.
func GatewayConfig(org string) (map[string]any, error) {
	files, err := openOrg(org)
	if err != nil {
		return nil, err
	}
	defer files.close()
	config, err := files.toml(".laneboss/org.toml", "org.toml")
	if err != nil {
		return nil, err
	}
	services, _ := config["services"].(map[string]any)
	service, ok := services["discord"].(map[string]any)
	if !ok {
		return nil, refused("org.toml requires a services.discord table")
	}
	guild, err := checkedString(service["guild_id"], "services.discord.guild_id", idPattern)
	if err != nil {
		return nil, err
	}
	secret, err := checkedString(service["token_secret"], "services.discord.token_secret", secretPattern)
	if err != nil {
		return nil, err
	}
	if owner, exists := service["owner_id"]; exists {
		if _, err := checkedString(owner, "services.discord.owner_id", idPattern); err != nil {
			return nil, err
		}
	}
	roles, err := readRoles(files, false)
	if err != nil {
		return nil, err
	}
	if len(roles) == 0 {
		return nil, refused("the Discord gateway requires at least one registered role")
	}
	if problems := ValidateOrgChannels(files.path); len(problems) != 0 {
		return nil, refused("Discord channel coverage is invalid; run org validate")
	}
	entries := map[string]any{}
	for _, name := range sortedNames(roles) {
		role := roles[name]
		entry := role.document()
		for key, filename := range map[string]string{"events_file": role.EventsFile, "state_file": role.StateFile} {
			relative := filepath.Join(".laneboss", "instances", role.Instance, "state", filename)
			if err := files.checkPath(relative); err != nil {
				return nil, err
			}
			entry[key] = filepath.Join(files.path, relative)
		}
		entries[name] = entry
	}
	state := filepath.Join(".laneboss", "shared", "state", "discord-gateway.state.json")
	lock := filepath.Join(".laneboss", "shared", "state", "discord-gateway.lock")
	for _, relative := range []string{state, lock} {
		if err := files.checkPath(relative); err != nil {
			return nil, err
		}
	}
	return map[string]any{"schema_version": 1, "org_dir": files.path, "guild_id": guild,
		"token_env": secret, "roles": entries, "gateway_state_file": filepath.Join(files.path, state),
		"lock_file": filepath.Join(files.path, lock)}, nil
}

func runRead(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(stdout, "usage: laneboss org channel read ORG --json")
		return 0
	}
	var org string
	jsonFlag := false
	for _, arg := range args {
		if arg == "--json" && !jsonFlag {
			jsonFlag = true
		} else if org == "" && len(arg) > 0 && arg[0] != '-' {
			org = arg
		} else {
			fmt.Fprintln(stderr, "laneboss org channel read: "+cliargs.Reject(""))
			return 2
		}
	}
	if org == "" || !jsonFlag {
		fmt.Fprintln(stderr, "usage: laneboss org channel read ORG --json")
		return 2
	}
	result, err := GatewayConfig(org)
	if err != nil {
		fmt.Fprintln(stderr, "laneboss org channel read: "+err.Error())
		return 2
	}
	if err := writeJSON(stdout, result); err != nil {
		fmt.Fprintln(stderr, "cannot write Discord configuration")
		return 2
	}
	return 0
}
