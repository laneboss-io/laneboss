//go:build laneboss_partial && laneboss_e2e_authenticator

package admin

// The installed E2E's stand-in build journals a masked refusal's fixed message (item 1 diagnosis); production builds
// never do (credential_owner_diag_linux.go).
const credentialOwnerDetail = true
