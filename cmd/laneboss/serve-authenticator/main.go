//go:build laneboss_e2e_authenticator

// Command serve-authenticator replaces only the unavailable hardware device
// and its presence/verification gesture. It never issues a proof or ticket.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

const program = "laneboss-serve-authenticator"
const version = "1.0.0"

type descriptor struct {
	Schema          string `json:"schema"`
	Program         string `json:"program"`
	Version         string `json:"version"`
	HardwareStoodIn bool   `json:"hardware_stood_in"`
	Presence        string `json:"presence"`
	AAGUID          string `json:"aaguid"`
	Attestation     string `json:"attestation_marker"`
	Gesture         string `json:"gesture"`
	Enrolled        bool   `json:"enrolled"`
	Config          string `json:"config"`
	PrincipalID     api.ID `json:"principal_id"`
	CredentialID    api.ID `json:"credential_id"`
	RawCredentialID []byte `json:"raw_credential_id"`
	Algorithm       string `json:"algorithm"`
	PublicKeyDER    []byte `json:"public_key_der"`
	Origin          string `json:"origin"`
	RPID            string `json:"rp_id"`
}

type options struct {
	Mode, Private, Config, Origin, RPID  string
	Operation, Challenge, Method, Target string
	Generation                           uint64
	Invited                              bool
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var configuration = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func parse(args []string) (options, error) {
	var result options
	if len(args) == 0 {
		return result, errors.New("authenticator mode required")
	}
	result.Mode = args[0]
	set := flag.NewFlagSet(program, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.StringVar(&result.Private, "private", "", "private test directory")
	set.StringVar(&result.Config, "config", "", "installed configuration")
	set.StringVar(&result.Origin, "origin", "", "enrolled origin")
	set.StringVar(&result.RPID, "rp-id", "", "enrolled relying party")
	set.StringVar(&result.Operation, "operation", "", "exact operation body")
	set.StringVar(&result.Challenge, "challenge", "", "installed challenge reply")
	set.StringVar(&result.Method, "method", "", "exact operation method")
	set.StringVar(&result.Target, "target", "", "actual operation target")
	set.Uint64Var(&result.Generation, "generation", 0, "actual base generation")
	set.BoolVar(&result.Invited, "invited", false, "create a distinct invited test credential")
	if set.Parse(args[1:]) != nil || set.NArg() != 0 || !configuration.MatchString(result.Config) {
		return result, errors.New("invalid authenticator arguments")
	}
	if result.Invited && result.Mode != "create" {
		return result, errors.New("invited applies only to device creation")
	}
	switch result.Mode {
	case "create":
		if result.Operation != "" || result.Challenge != "" || result.Method != "" || result.Target != "" ||
			result.Generation != 0 || originPolicy(result.Origin, result.RPID) != nil {
			return result, errors.New("invalid authenticator enrollment proposal")
		}
	case "register":
		if result.Challenge == "" || result.Operation != "" || result.Method != "" || result.Target != "" ||
			result.Generation != 0 || result.Origin != "" || result.RPID != "" {
			return result, errors.New("invalid registration invocation")
		}
	case "intent", "sign":
		if result.Operation == "" || !identifier.MatchString(result.Target) || result.Generation > 1<<53-1 ||
			result.Origin != "" || result.RPID != "" || result.Mode == "sign" && result.Challenge == "" ||
			result.Mode == "intent" && result.Challenge != "" {
			return result, errors.New("invalid authenticator intent")
		}
	default:
		return result, errors.New("unknown authenticator mode")
	}
	return result, nil
}

func originPolicy(origin, rp string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() != rp || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || rp == "" {
		return errors.New("fixture requires its exact HTTPS relying party")
	}
	return nil
}

func openPrivate(path string) (*os.Root, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || resolved != path || path == "/" {
		return nil, errors.New("private authenticator directory required")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("unsafe authenticator directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("authenticator directory owner differs")
	}
	return os.OpenRoot(path)
}

func writePrivate(root *os.Root, name string, data []byte) error {
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("preserve existing authenticator state")
	}
	_, writeErr := file.Write(data)
	return errors.Join(writeErr, file.Sync(), file.Close())
}

func readPrivate(root *os.Root, name string) ([]byte, error) {
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() < 1 || before.Size() > 16384 {
		return nil, errors.New("unsafe authenticator state")
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return nil, errors.New("authenticator state ownership differs")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, errors.New("authenticator state cannot open")
	}
	after, statErr := file.Stat()
	data, readErr := io.ReadAll(io.LimitReader(file, 16385))
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !os.SameFile(before, after) || int64(len(data)) != before.Size() {
		clear(data)
		return nil, errors.New("authenticator state changed during read")
	}
	return data, nil
}

func freshID(prefix string) (api.ID, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", errors.New("authenticator entropy unavailable")
	}
	return api.ID(prefix + hex.EncodeToString(data)), nil
}

func create(root *os.Root, input options) (descriptor, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return descriptor{}, errors.New("authenticator key generation failed")
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return descriptor{}, errors.New("authenticator key encoding failed")
	}
	defer clear(private)
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return descriptor{}, err
	}
	principal, err := freshID("serve-human-")
	if err != nil {
		return descriptor{}, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return descriptor{}, errors.New("authenticator credential entropy unavailable")
	}
	raw = append([]byte(api.SoftwareAuthenticatorRawPrefix), raw...)
	publicData := descriptor{Schema: "laneboss.software-auth.v1", Program: program, Version: version,
		HardwareStoodIn: true, Gesture: "simulated UP and UV", Config: input.Config,
		Presence: "simulated", AAGUID: api.SoftwareAuthenticatorAAGUID, Attestation: api.SoftwareAuthenticatorAttestationMarker,
		PrincipalID: principal, CredentialID: api.SoftwareAuthenticatorCredentialID, RawCredentialID: raw, Algorithm: "ES256",
		PublicKeyDER: public, Origin: input.Origin, RPID: input.RPID}
	if input.Invited {
		publicData.CredentialID = api.InvitedCredentialID(raw)
	}
	data, err := json.Marshal(publicData)
	if err != nil {
		return descriptor{}, err
	}
	for _, entry := range []struct {
		name string
		data []byte
	}{
		{"key.der", private}, {"counter", make([]byte, 4)}, {"public.json", data},
	} {
		if err := writePrivate(root, entry.name, entry.data); err != nil {
			return descriptor{}, err
		}
	}
	return publicData, nil
}

func operationIntent(input options, raw []byte) (api.HumanChallengeRequest, error) {
	method := api.Method(input.Method)
	spec, ok := api.Methods[method]
	if !ok || !spec.Mutation || spec.Access == "human-endpoint" {
		return api.HumanChallengeRequest{}, errors.New("unsupported confirmation intent")
	}
	body := reflect.New(spec.Request).Interface()
	if err := api.DecodeObject(raw, body); err != nil {
		return api.HumanChallengeRequest{}, err
	}
	digest, err := api.RequestDigest(api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
		Config: input.Config, Method: method, Params: raw})
	return api.HumanChallengeRequest{Method: method, TargetID: api.ID(input.Target),
		RequestSHA256: digest, BaseGeneration: api.Generation(input.Generation)}, err
}

func sign(root *os.Root, input options, intent api.HumanChallengeRequest, raw []byte, now time.Time) (api.HumanConfirmRequest, error) {
	var result api.HumanConfirmRequest
	var challenge api.HumanChallenge
	if api.DecodeObject(raw, &challenge) != nil || challenge.Config != input.Config ||
		challenge.Method != intent.Method || challenge.TargetID != intent.TargetID ||
		challenge.RequestSHA256 != intent.RequestSHA256 || challenge.BaseGeneration != intent.BaseGeneration ||
		!identifier.MatchString(string(challenge.ID)) || len(challenge.Challenge) < 32 || len(challenge.Challenge) > 128 {
		return result, errors.New("challenge differs from exact operation")
	}
	expires, err := time.Parse(time.RFC3339Nano, string(challenge.ExpiresAt))
	if err != nil || !now.Before(expires) || expires.After(now.Add(120*time.Second)) {
		return result, errors.New("challenge lifetime invalid")
	}
	metadata, err := readPrivate(root, "public.json")
	if err != nil {
		return result, err
	}
	var public descriptor
	if api.DecodeObject(metadata, &public) != nil || public.Config != input.Config || public.Program != program ||
		!public.HardwareStoodIn || public.Enrolled || public.Origin != challenge.Origin || public.RPID != challenge.RPID ||
		public.Presence != "simulated" || (public.CredentialID != api.SoftwareAuthenticatorCredentialID && public.CredentialID != api.InvitedCredentialID(public.RawCredentialID)) || public.AAGUID != api.SoftwareAuthenticatorAAGUID ||
		public.Attestation != api.SoftwareAuthenticatorAttestationMarker || !bytes.HasPrefix(public.RawCredentialID, []byte(api.SoftwareAuthenticatorRawPrefix)) ||
		originPolicy(public.Origin, public.RPID) != nil {
		return result, errors.New("challenge relying party differs from private credential")
	}
	private, err := readPrivate(root, "key.der")
	if err != nil {
		return result, err
	}
	defer clear(private)
	parsed, err := x509.ParsePKCS8PrivateKey(private)
	if err != nil {
		return result, errors.New("private authenticator key invalid")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return result, errors.New("private authenticator algorithm differs")
	}
	actual, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil || !bytes.Equal(actual, public.PublicKeyDER) {
		return result, errors.New("authenticator public pin differs")
	}
	if err := writePrivate(root, "signing.lock", []byte{1}); err != nil {
		return result, err
	}
	// A crash retains this lock. Do not reset a counter or repair private state.
	counterBytes, err := readPrivate(root, "counter")
	if err != nil || len(counterBytes) != 4 {
		return result, errors.New("authenticator counter invalid")
	}
	counter := binary.BigEndian.Uint32(counterBytes)
	if counter == ^uint32(0) {
		return result, errors.New("authenticator counter exhausted")
	}
	counter++
	binary.BigEndian.PutUint32(counterBytes, counter)
	if err := writePrivate(root, "counter.next", counterBytes); err != nil {
		return result, err
	}
	if err := root.Rename("counter.next", "counter"); err != nil {
		return result, errors.New("counter persistence failed")
	}
	directory, err := root.Open(".")
	if err != nil {
		return result, errors.New("counter directory cannot open")
	}
	if err := errors.Join(directory.Sync(), directory.Close()); err != nil {
		return result, errors.New("counter directory sync failed")
	}
	// Exact WebAuthn names are case-sensitive, including crossOrigin.
	clientData, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(challenge.Challenge),
		"origin": challenge.Origin, "crossOrigin": false})
	if err != nil {
		return result, err
	}
	rp := sha256.Sum256([]byte(challenge.RPID))
	authenticator := append([]byte{}, rp[:]...)
	authenticator = append(authenticator, 0x05)
	authenticator = append(authenticator, counterBytes...)
	clientHash := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authenticator...), clientHash[:]...)
	hash := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		return result, errors.New("authenticator signing failed")
	}
	if err := root.Remove("signing.lock"); err != nil {
		return result, errors.New("authenticator lock release failed")
	}
	return api.HumanConfirmRequest{ChallengeID: challenge.ID, CredentialID: public.CredentialID,
		ClientDataJSON: clientData, AuthenticatorData: authenticator, Signature: signature}, nil
}

func readInput(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("authenticator input cannot open")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > api.MaxFrameBytes {
		return nil, errors.New("authenticator input is not bounded")
	}
	data, err := io.ReadAll(io.LimitReader(file, api.MaxFrameBytes+1))
	if err != nil || int64(len(data)) != info.Size() {
		return nil, errors.New("authenticator input changed")
	}
	return data, nil
}

func execute(input options, output io.Writer) error {
	if runtime.GOOS != "linux" {
		return errors.New("authenticator fixture requires Linux")
	}
	if input.Mode == "intent" {
		raw, err := readInput(input.Operation)
		if err != nil {
			return err
		}
		intent, err := operationIntent(input, raw)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(intent)
	}
	root, err := openPrivate(input.Private)
	if err != nil {
		return err
	}
	defer root.Close()
	if input.Mode == "create" {
		public, err := create(root, input)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(public)
	}
	if input.Mode == "register" {
		data, err := readInput(input.Challenge)
		if err != nil {
			return err
		}
		registration, err := register(root, input.Config, data, time.Now().UTC())
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(registration)
	}
	raw, err := readInput(input.Operation)
	if err != nil {
		return err
	}
	intent, err := operationIntent(input, raw)
	if err != nil {
		return err
	}
	challenge, err := readInput(input.Challenge)
	if err != nil {
		return err
	}
	assertion, err := sign(root, input, intent, challenge, time.Now().UTC())
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(assertion)
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		if json.NewEncoder(os.Stdout).Encode(map[string]any{"program": program, "version": version,
			"hardware_stood_in": true, "gesture": "simulated UP and UV", "presence": "simulated",
			"aaguid": api.SoftwareAuthenticatorAAGUID, "attestation_marker": api.SoftwareAuthenticatorAttestationMarker,
			"credential_id": api.SoftwareAuthenticatorCredentialID, "raw_prefix": api.SoftwareAuthenticatorRawPrefix,
			"build_tag": api.SoftwareAuthenticatorBuildTag}) != nil {
			os.Exit(1)
		}
		return
	}
	input, err := parse(os.Args[1:])
	if err == nil {
		err = execute(input, os.Stdout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "software authenticator stopped; preserve private state")
		os.Exit(1)
	}
}
