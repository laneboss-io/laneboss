//go:build laneboss_partial && laneboss_e2e_authenticator

package secrets

// standInAgentRole is the installed E2E stand-in's agent object role (scripts/v2-serve/provision.py,
// assembly/fixture.go); only the stand-in build accepts it beside "agent".
const standInAgentRole = "serve-fixture-agent"
