package orgtree

// rawTaskBlacklist is installed only by org init. Rendering an existing org
// never inserts policy; its owner can opt in by editing org.toml explicitly.
func rawTaskBlacklist() []any {
	const sessions = "laneboss lane start / laneboss lane resume / laneboss lane turn"
	entries := []struct {
		id, description, instead string
		argv                     []any
	}{
		{"raw-codex-exec", "Starting a raw Codex agent session bypasses the lane lifecycle.", sessions, []any{"codex", "exec"}},
		{"raw-claude-p", "Starting a raw Claude print session bypasses the lane lifecycle.", sessions, []any{"claude", "-p"}},
		{"raw-claude-print", "Starting a raw Claude print session bypasses the lane lifecycle.", sessions, []any{"claude", "--print"}},
		{"raw-claudock-run", "Starting a raw Claudock agent session bypasses the lane lifecycle.", sessions, []any{"claudock", "run"}},
		{"raw-tmux-new-session", "Creating a raw tmux session bypasses lane start.", "laneboss lane start", []any{"tmux", "new-session"}},
		{"raw-tmux-new", "Creating a raw tmux session bypasses lane start.", "laneboss lane start", []any{"tmux", "new"}},
		{"raw-tmux-kill-session", "Killing a raw tmux session bypasses lane stop.", "laneboss lane stop", []any{"tmux", "kill-session"}},
		{"raw-tmux-send-keys", "Sending raw tmux input bypasses lane attach.", "laneboss lane attach", []any{"tmux", "send-keys"}},
		{"raw-tmux-attach", "Attaching to raw tmux bypasses lane attach.", "laneboss lane attach", []any{"tmux", "attach"}},
		{"raw-tmux-attach-session", "Attaching to raw tmux bypasses lane attach.", "laneboss lane attach", []any{"tmux", "attach-session"}},
		{"raw-aws-run-instances", "Creating a raw EC2 test machine bypasses laneboss box.", "laneboss box", []any{"aws", "ec2", "run-instances"}},
		{"raw-gcloud-instances-create", "Creating a raw Compute Engine test machine bypasses laneboss box.", "laneboss box", []any{"gcloud", "compute", "instances", "create"}},
	}
	rows := make([]any, 0, len(entries))
	for _, entry := range entries {
		rows = append(rows, map[string]any{
			"id": entry.id, "description": entry.description, "band": "refuse",
			"argv_words": entry.argv, "instead": entry.instead, "pattern_only": true,
		})
	}
	return rows
}
