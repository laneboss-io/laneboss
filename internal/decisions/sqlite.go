package decisions

// The event store and the decision store are SQLite files shared with the Python launcher while the port lands:
// every package opens them with this one pinned pure-Go driver, and keeps their schemas byte-compatible.
import _ "modernc.org/sqlite"
