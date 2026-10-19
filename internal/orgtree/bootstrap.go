package orgtree

// Init creates the same sources and instances as org init, including L5-top.
func Init(root, name string) error {
	_, err := initOrg(root, "3-6", &name)
	return err
}

// Validate checks the tree and its generated hooks without starting a runner.
func Validate(root string) error {
	report := validateOrg(root)
	return problemsError(report.Problems)
}
