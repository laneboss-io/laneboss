package orgdiscord

// Installed checks existing configuration and the private token through the same
// readers as delivery, without making a network request or returning the token.
func Installed(org, target string) (bool, error) {
	files, err := openOrg(org)
	if err != nil {
		return false, err
	}
	defer files.close()
	document, err := files.toml(".laneboss/org.toml", "org.toml")
	if err != nil {
		return false, err
	}
	services, _ := document["services"].(map[string]any)
	if services["discord"] == nil {
		return false, nil
	}
	roles, err := readRoles(files, true)
	if err != nil {
		return false, err
	}
	matched := false
	for name, role := range roles {
		if name == target || role.Instance == target {
			matched = true
			break
		}
	}
	if !matched {
		return false, nil
	}
	discord, store, err := settings(files)
	if err != nil {
		return false, err
	}
	_, err = loadToken(discord, store)
	if err != nil {
		return false, err
	}
	return true, nil
}
