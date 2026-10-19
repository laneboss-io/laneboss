//go:build !(laneboss_partial && laneboss_e2e_authenticator)

package secrets

// Production builds have no stand-in role. Canonical vendor files are checked
// separately against the protected installation in projection.go.
const standInAgentRole = ""
