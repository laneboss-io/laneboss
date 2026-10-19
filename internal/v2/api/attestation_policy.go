package api

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"regexp"
)

// InstalledAttestationPolicy is protected administrator boot data. Root DER
// contains public CA certificates, never a private key or enrollment input.
type InstalledAttestationPolicy struct {
	Schema                 string     `json:"schema"`
	Config                 string     `json:"config"`
	InstallationGeneration Generation `json:"installation_generation"`
	RootsDER               [][]byte   `json:"roots_der"`
	AllowedAAGUIDs         []string   `json:"allowed_aaguids,omitempty"`
}

var installedAAGUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Empty roots explicitly close production registration without inventing trust.
// Certificate validity at ceremony time remains identity's chain-verification
// duty. This validator parses CA pins; it does not prove protected file origin.
func ValidateInstalledAttestationPolicy(policy InstalledAttestationPolicy, config string, installation Generation) error {
	if policy.Schema != "laneboss.attestation-trust.v2" || !bindingConfigName.MatchString(config) || policy.Config != config ||
		!launchGeneration(installation) || policy.InstallationGeneration != installation ||
		len(policy.RootsDER) > 32 || len(policy.AllowedAAGUIDs) > 256 ||
		len(policy.RootsDER) == 0 && len(policy.AllowedAAGUIDs) != 0 {
		return launchInvalid("invalid installed attestation policy context")
	}
	seen, keys := map[[32]byte]bool{}, map[[32]byte]bool{}
	total := 0
	for _, der := range policy.RootsDER {
		total += len(der)
		if len(der) == 0 || len(der) > 65536 || total > 512<<10 {
			return launchInvalid("attestation root bytes exceed their bound")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil || !cert.BasicConstraintsValid || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return launchInvalid("attestation root is not a pinned certificate authority")
		}
		if !bytes.Equal(cert.RawIssuer, cert.RawSubject) || cert.CheckSignatureFrom(cert) != nil {
			return launchInvalid("attestation pin is not a self-signed root")
		}
		digest := sha256.Sum256(der)
		if seen[digest] {
			return launchInvalid("attestation policy repeats a root")
		}
		seen[digest] = true
		key := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		if keys[key] {
			return launchInvalid("attestation policy repeats a root public key")
		}
		keys[key] = true
	}
	names := map[string]bool{}
	for _, name := range policy.AllowedAAGUIDs {
		if !installedAAGUID.MatchString(name) || names[name] {
			return launchInvalid("attestation AAGUID is not canonical or is repeated")
		}
		names[name] = true
	}
	return nil
}

func CloneInstalledAttestationPolicy(policy InstalledAttestationPolicy) InstalledAttestationPolicy {
	result := policy
	result.RootsDER = make([][]byte, len(policy.RootsDER))
	for i, der := range policy.RootsDER {
		result.RootsDER[i] = append([]byte(nil), der...)
	}
	result.AllowedAAGUIDs = append([]string(nil), policy.AllowedAAGUIDs...)
	return result
}
