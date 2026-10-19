package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"

	"laneboss.io/laneboss/internal/v2/api"
)

var enrollmentConfigName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func (s *Service) BeginEnrollment(ctx context.Context, request api.EnrollmentCeremonyRequest) (api.EnrollmentChallenge, error) {
	if err := ctx.Err(); err != nil {
		return api.EnrollmentChallenge{}, err
	}
	if !enrollmentConfigName.MatchString(request.Config) || !validID(request.CeremonyID) || !validID(request.PrincipalID) || request.ExpectedGeneration >= 1<<53-1 {
		return api.EnrollmentChallenge{}, refusal(api.CodeInvalid, "invalid enrollment ceremony")
	}
	challenge, err := s.deps.Store.ReserveEnrollment(ctx, request)
	if err != nil {
		return api.EnrollmentChallenge{}, err
	}
	if err := api.ValidateEnrollmentChallenge(challenge, request, s.deps.Clock.Now()); err != nil {
		return api.EnrollmentChallenge{}, err
	}
	challenge.Challenge = append([]byte(nil), challenge.Challenge...)
	return challenge, nil
}

func (s *Service) ValidateEnrollment(ctx context.Context, request api.EnrollmentValidationRequest) (api.EnrollmentInstall, error) {
	if err := ctx.Err(); err != nil {
		return api.EnrollmentInstall{}, err
	}
	if !validID(request.ChallengeID) || len(request.ClientDataJSON) == 0 || len(request.AttestationObject) == 0 ||
		len(request.ClientDataJSON)+len(request.AttestationObject) > api.MaxFrameBytes || len(request.AttestationMarker) > 128 {
		return api.EnrollmentInstall{}, registrationInvalid()
	}
	request.ClientDataJSON = append([]byte(nil), request.ClientDataJSON...)
	request.AttestationObject = append([]byte(nil), request.AttestationObject...)
	challenge, err := s.deps.Store.EnrollmentChallenge(ctx, request.Ceremony.Config, request.ChallengeID)
	if err != nil {
		return api.EnrollmentInstall{}, err
	}
	if err := api.ValidateEnrollmentChallenge(challenge, request.Ceremony, s.deps.Clock.Now()); err != nil {
		return api.EnrollmentInstall{}, err
	}
	if challenge.ID != request.ChallengeID {
		return api.EnrollmentInstall{}, refusal(api.CodeIntegrity, "registration challenge selector changed")
	}
	credential, err := s.verifyRegistration(challenge, request)
	if err != nil {
		return api.EnrollmentInstall{}, err
	}
	validationID, err := newID()
	if err != nil {
		return api.EnrollmentInstall{}, err
	}
	// The administrator transaction retains this exact typed request (whose
	// byte fields preserve the original client data and attestation) as a private
	// ObjectWrite, together with challenge consumption and the enrollment. This
	// validation handoff does not claim an earlier standalone durable commit.
	bytes, err := json.Marshal(request)
	if err != nil {
		return api.EnrollmentInstall{}, err
	}
	evidence := api.BlobRef{ID: validationID, Class: "artifact", SHA256: digestBytes(bytes), Bytes: int64(len(bytes))}
	credential.RegistrationEvidence = evidence
	install := api.EnrollmentInstall{CeremonyID: request.Ceremony.CeremonyID, ChallengeID: challenge.ID, ValidationID: validationID,
		ExpectedGeneration: request.Ceremony.ExpectedGeneration, CeremonyEvidence: evidence,
		Enrollment: api.HumanEnrollment{Config: challenge.Ceremony.Config, PrincipalID: challenge.Ceremony.PrincipalID,
			Origin: challenge.Origin, RPID: challenge.RPID, Generation: request.Ceremony.ExpectedGeneration + 1,
			Credentials: []api.HumanCredential{credential}}}
	if err := api.ValidateEnrollmentInstall(challenge, request, install, s.deps.Clock.Now()); err != nil {
		return api.EnrollmentInstall{}, err
	}
	return install, nil
}

func (s *Service) verifyRegistration(challenge api.EnrollmentChallenge, request api.EnrollmentValidationRequest) (api.HumanCredential, error) {
	var empty api.HumanCredential
	client, err := decodeClientData(request.ClientDataJSON)
	if err != nil {
		return empty, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(challenge.Challenge)
	if client.Type != "webauthn.create" || client.CrossOrigin || client.TopOrigin != nil || client.Origin != challenge.Origin ||
		subtle.ConstantTimeCompare([]byte(client.Challenge), []byte(nonce)) != 1 {
		return empty, refusal(api.CodeUnauthenticated, "registration ceremony, origin or nonce differs")
	}
	object, err := cborObject(request.AttestationObject)
	if err != nil || len(object) != 3 {
		return empty, registrationInvalid()
	}
	format, formatOK := object["fmt"].(string)
	auth, authOK := object["authData"].([]byte)
	statement, statementOK := object["attStmt"].(map[any]any)
	if !formatOK || !authOK || !statementOK || len(auth) < 55 {
		return empty, registrationInvalid()
	}
	rpHash := sha256.Sum256([]byte(challenge.RPID))
	flags := auth[32]
	if subtle.ConstantTimeCompare(auth[:32], rpHash[:]) != 1 || flags&0x45 != 0x45 || flags&0xa2 != 0 || flags&0x10 != 0 && flags&0x08 == 0 {
		return empty, refusal(api.CodeUnauthenticated, "registration RP or presence flags differ")
	}
	length := int(binary.BigEndian.Uint16(auth[53:55]))
	if length == 0 || length > 1023 || length > len(auth)-55 {
		return empty, registrationInvalid()
	}
	rawID := auth[55 : 55+length]
	key, algorithm, err := registrationKey(auth[55+length:])
	if err != nil {
		return empty, err
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return empty, registrationInvalid()
	}
	a := hex.EncodeToString(auth[37:53])
	aaguid := fmt.Sprintf("%s-%s-%s-%s-%s", a[:8], a[8:12], a[12:16], a[16:20], a[20:])
	credential := api.HumanCredential{ID: api.ID("credential-" + string(digestBytes(rawID))), RawCredentialID: append([]byte(nil), rawID...),
		AAGUID: aaguid, AttestationFormat: format, AttestationMarker: request.AttestationMarker,
		SimulatedPresence: aaguid == api.SoftwareAuthenticatorAAGUID && request.AttestationMarker == api.SoftwareAuthenticatorAttestationMarker,
		Algorithm:         algorithm, PublicKeyDER: der, Counter: registrationCounter(auth), Generation: 1}
	credential = normalizeRegistration(credential)
	if err := api.ValidateCredentialPresence(credential); err != nil {
		return empty, err
	}
	if err := s.verifyAttestation(challenge, credential, statement, auth, request.ClientDataJSON, key); err != nil {
		return empty, err
	}
	return credential, nil
}

func normalizeRegistration(credential api.HumanCredential) api.HumanCredential {
	// This flag was derived from the verified reserved AAGUID/marker pair.
	// Preserve every presence/evidence/key byte; production policy still refuses.
	if credential.SimulatedPresence {
		credential.ID = api.SoftwareAuthenticatorCredentialID
	}
	return credential
}

func registrationKey(raw []byte) (any, string, error) {
	object, err := cborObject(raw)
	if err != nil {
		return nil, "", err
	}
	kind, kindOK := object[int64(1)].(int64)
	algorithm, algorithmOK := object[int64(3)].(int64)
	if !kindOK || !algorithmOK {
		return nil, "", registrationInvalid()
	}
	for label := range object {
		i, ok := label.(int64)
		if !ok || i != 1 && i != 3 && i != -1 && i != -2 && i != -3 {
			return nil, "", registrationInvalid()
		}
	}
	x, xOK := object[int64(-2)].([]byte)
	switch {
	case kind == 2 && algorithm == -7 && object[int64(-1)] == int64(1):
		y, ok := object[int64(-3)].([]byte)
		if !xOK || !ok || len(x) != 32 || len(y) != 32 || len(object) != 5 {
			return nil, "", registrationInvalid()
		}
		key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !key.Curve.IsOnCurve(key.X, key.Y) {
			return nil, "", registrationInvalid()
		}
		return key, "ES256", nil
	case kind == 1 && algorithm == -8 && object[int64(-1)] == int64(6):
		if !xOK || len(x) != ed25519.PublicKeySize || len(object) != 4 {
			return nil, "", registrationInvalid()
		}
		return ed25519.PublicKey(append([]byte(nil), x...)), "Ed25519", nil
	case kind == 3 && algorithm == -257:
		n, ok := object[int64(-1)].([]byte)
		if !ok || !xOK || len(n) < 256 || len(n) > 1024 || len(x) == 0 || len(x) > 4 || len(object) != 4 {
			return nil, "", registrationInvalid()
		}
		e := new(big.Int).SetBytes(x).Int64()
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(e)}
		if key.N.BitLen() < 2048 || e < 65537 || e > 1<<31-1 || e&1 == 0 {
			return nil, "", registrationInvalid()
		}
		return key, "RS256", nil
	}
	return nil, "", refusal(api.CodeUnsupported, "registration COSE algorithm is unsupported")
}
