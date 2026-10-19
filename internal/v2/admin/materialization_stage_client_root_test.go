//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/service"
)

func TestMaterializationNativeStoreClient(t *testing.T) {
	if os.Args[len(os.Args)-1] != "materialization-store-client" {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestMaterializationNative$", "-test.v")
		command.Env = []string{}
		if output, err := command.CombinedOutput(); err != nil || !bytes.Contains(output, []byte("--- PASS: TestMaterializationNative ")) {
			t.Fatalf("native stage root kit failed: %v\n%s", err, output)
		}
		return
	}
	metadata, requests, replies := os.NewFile(3, "materialization-native-metadata"), os.NewFile(4, "materialization-native-requests"), os.NewFile(5, "materialization-native-replies")
	defer metadata.Close()
	defer requests.Close()
	defer replies.Close()
	var meta service.MaterializationCanaryMetadata
	if err := json.NewDecoder(metadata).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	encoder, decoder := json.NewEncoder(requests), json.NewDecoder(replies)
	service.ExerciseMaterializationCanary(t, meta, func(method string, input any) error {
		raw, err := json.Marshal(input)
		if err != nil {
			return err
		}
		if err := encoder.Encode(struct {
			Method string
			Input  json.RawMessage
		}{method, raw}); err != nil {
			return err
		}
		var reply struct{ Error *api.Error }
		if err := decoder.Decode(&reply); err != nil {
			return err
		}
		if reply.Error != nil {
			return reply.Error
		}
		return nil
	})
}
