package hookconfig

// Darwin has no Linux bind mounts. Symlinks, file links and inode identity are
// checked by vetStateRoot; the laneboss-files wrapper retains its own deny list.
func stateMount(path string) error { return nil }
