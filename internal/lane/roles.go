package lane

func screenRoleSource(data []byte) error {
	if rule, _ := credential(string(data)); rule != "" {
		return refuse("org role source looks like a credential (%s); nothing was written", rule)
	}
	return nil
}
