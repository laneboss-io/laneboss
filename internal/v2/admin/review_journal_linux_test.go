//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestReviewJournalWire(t *testing.T) {
	m, memory, _ := testManager()
	if _, err := m.allocate(context.Background(), testAllocation()); err != nil {
		t.Fatal(err)
	}
	p := memory.records[0]
	archive := archiveClaimFixture()
	p.Archive = &archiveJournal{Intent: archive.Job.Intent, LaunchID: "archival-launch", Phase: "withdrawing", Tree: api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}}, Inventory: []storageInode{}}
	review := *p.Archive
	review.Intent.OperationID = "independent-review-operation"
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["reviews"], err = json.Marshal([]archiveJournal{review})
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	var retained leaseRecord
	if err := decodeStrict(raw, &retained); err != nil {
		t.Fatal("native helper lacks an independent durable review journal", err)
	}
	root, err := os.OpenRoot(privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	journal := &fileLeaseStore{root: root, owner: uint32(os.Geteuid())}
	if err := journal.Save(retained); err != nil {
		t.Fatal(err)
	}
	read, err := journal.Records()
	if err != nil || len(read) != 1 || !reflect.DeepEqual(retained, read[0]) || !reflect.DeepEqual(read[0].Archive, p.Archive) {
		t.Fatal("native review persistence replaced the original archival journal", err)
	}
	var result map[string]json.RawMessage
	actual, err := json.Marshal(read[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(actual, &result); err != nil {
		t.Fatal(err)
	}
	var reviews []archiveJournal
	if err := json.Unmarshal(result["reviews"], &reviews); err != nil || len(reviews) != 1 || reviews[0].Intent.OperationID != review.Intent.OperationID {
		t.Fatal("native review journal lost its own original operation", err)
	}
}
