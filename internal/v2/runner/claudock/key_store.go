package claudock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

const KeyProfile = "lane-key"
const KeyStorePath = ".config/claudock/key-store.json"

// Claudock hashes the credential service, including the directory suffix of
// a managed profile. The logical directory is fixed in the private namespace.
func keyService() string {
	directory := sha256.Sum256([]byte(VendorDirectory))
	service := sha256.Sum256([]byte("Claude Code-credentials-" + hex.EncodeToString(directory[:4])))
	return "Claudock-apikey-" + hex.EncodeToString(service[:])
}

type keyStore struct {
	Version int               `json:"version"`
	Items   map[string]string `json:"items"`
}

// EncodeKeyStore is used only by the credential worker on the selected slot.
// Its result is credential material and must never enter records or logs.
func EncodeKeyStore(key []byte) ([]byte, error) {
	if err := (APIKeyValidator{}).ValidateAPIKeyCredential("slot", "slot", key); err != nil {
		return nil, err
	}
	return json.Marshal(keyStore{Version: 1, Items: map[string]string{keyService(): string(key)}})
}

func DecodeKeyStore(data []byte) ([]byte, error) {
	var store keyStore
	if decodeExact(data, &store) != nil || store.Version != 1 || len(store.Items) != 1 {
		return nil, failure(api.CodeIntegrity, "API key store differs from its private slot")
	}
	key := []byte(store.Items[keyService()])
	if err := (APIKeyValidator{}).ValidateAPIKeyCredential("slot", "slot", key); err != nil {
		clear(key)
		return nil, err
	}
	return key, nil
}
