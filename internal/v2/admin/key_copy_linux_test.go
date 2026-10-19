//go:build linux

package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

func TestKeyStoreCopy(t *testing.T) {
	var entropy [24]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal(err)
	}
	key := []byte("sk-ant-api03-" + hex.EncodeToString(entropy[:]))
	defer clear(key)
	for _, fault := range []string{"none", "short", "long", "shape"} {
		t.Run(fault, func(t *testing.T) {
			material := bytes.Clone(key)
			defer clear(material)
			size := int64(len(material))
			switch fault {
			case "short":
				size++
			case "long":
				size--
			case "shape":
				material[0] = '!'
			}
			input, err := os.CreateTemp(t.TempDir(), "slot-")
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			if _, err := input.Write(material); err != nil {
				t.Fatal(err)
			}
			output, err := os.CreateTemp(t.TempDir(), "store-")
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			err = copyKeyStore(context.Background(), input, output, size)
			if fault != "none" {
				if err == nil {
					t.Fatal("invalid slot bytes became a vendor store")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(output.Name())
			if err != nil {
				t.Fatal(err)
			}
			defer clear(data)
			actual, err := claudock.DecodeKeyStore(data)
			defer clear(actual)
			if err != nil || !bytes.Equal(actual, key) || bytes.Equal(data, key) {
				t.Fatal("copy did not retain the selected key in the vendor store format")
			}
			if err := output.Close(); err != nil {
				t.Fatal(err)
			}
			reader, err := os.Open(output.Name())
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			a := api.CredentialProjectionAuthority{Request: api.CredentialProjectionRequest{Lease: api.HelperLease{UID: uint32(os.Getuid())},
				Handoff: api.PreparedSpecHandoff{Spec: api.LaunchSpec{Runner: &api.RunnerPlan{Driver: api.DriverClaudock,
					Slot: api.CredentialSlot{ID: "key-slot", Mode: "claude-api-key"}}}}}, Targets: []api.CredentialTarget{{SlotID: "key-slot", Delivery: "file",
				RelativePath: claudock.KeyStorePath, EnvironmentName: "ANTHROPIC_API_KEY", FileMode: 0600}}}
			recovered, err := releaseAPIKeyMaterial(&heldCredentials{files: []*os.File{reader}}, api.CredentialProjectionRecord{Authority: a})
			defer clear(recovered)
			if err != nil || !bytes.Equal(recovered, key) {
				t.Fatal("withdrawal lost its selected key scan material", err)
			}
		})
	}
}

func TestKeyStoreEnvironment(t *testing.T) {
	values := agentEnvironment(api.DriverClaudock, "claude-api-key")
	var registry, store string
	for _, value := range values {
		if bytes.HasPrefix([]byte(value), []byte("CLAUDOCK_REGISTRY_DIR=")) {
			registry = value[len("CLAUDOCK_REGISTRY_DIR="):]
		}
		if bytes.HasPrefix([]byte(value), []byte("CLAUDOCK_CREDENTIAL_STORE=")) {
			store = value[len("CLAUDOCK_CREDENTIAL_STORE="):]
		}
	}
	if registry != "/home/lane/.config/claudock" || store != "file:"+filepath.Join("/home/lane", claudock.KeyStorePath) {
		t.Fatal("API key environment omitted the explicit private registry or file store")
	}
}
