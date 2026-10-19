//go:build !(laneboss_partial && laneboss_e2e_authenticator)

package admin

// Production builds journal only the method, code and owner of a masked refusal.
const credentialOwnerDetail = false
