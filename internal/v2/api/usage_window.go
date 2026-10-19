package api

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"time"
)

type UsageWindowRequest struct {
	Target          LifeRef
	LaunchID        ID
	OperationID     ID
	ProfileGrantID  ID
	ProfileID       ID
	Provider        string
	RunEndedAt      Timestamp
	AdapterVersion  string
	Executable      Executable
	RuntimeManifest BlobRef
}

type UsageWindowEvidence struct {
	Schema             string     `json:"schema"`
	ID                 ID         `json:"id"`
	Target             LifeRef    `json:"target"`
	LaunchID           ID         `json:"launch_id"`
	OperationID        ID         `json:"operation_id"`
	ProfileGrantID     ID         `json:"profile_grant_id"`
	ProfileID          ID         `json:"profile_id"`
	Provider           string     `json:"provider"`
	AdapterVersion     string     `json:"adapter_version"`
	Executable         Executable `json:"executable"`
	RuntimeManifest    BlobRef    `json:"runtime_manifest"`
	WorkerLeaseID      ID         `json:"worker_lease_id"`
	ProducerID         ID         `json:"producer_id"`
	ProducerGeneration string     `json:"producer_generation"`
	BootID             string     `json:"boot_id"`
	ObservedAt         Timestamp  `json:"observed_at"`
	Window             string     `json:"window"`
	UsedPercent        float64    `json:"used_percent"`
	ResetsAt           Timestamp  `json:"resets_at"`
	ExitCode           int        `json:"exit_code"`
	Raw                BlobRef    `json:"raw"`
	Row                int        `json:"row"`
}

type UsageWindowSource interface {
	ReadUsageWindow(context.Context, Scope, UsageWindowRequest) (UsageWindowEvidence, error)
}

// UsageProvenance is private installed metadata, never an RPC result. The
// credential owner retains the authenticated producing job before publishing
// the envelope; consumers cannot reconstruct this tuple from envelope labels.
type UsageProvenance struct {
	Evidence        BlobRef
	Producer        WorkerPrincipal
	VendorProfile   string
	Executable      Executable
	RuntimeManifest BlobRef
}

type UsageProvenanceSource interface {
	ReadUsageProvenance(context.Context, Scope, BlobRef) (UsageProvenance, error)
}

// Authentication comes from the actual outside usage worker, never the lane's
// stdout or Room.Available=false. The producer pins the enrolled usage binary.
func ValidateUsageWindow(e UsageWindowEvidence, request UsageWindowRequest, producer WorkerPrincipal, now time.Time) error {
	if err := ValidateWorkerPrincipal(producer, producer.Endpoint, producer.Peer, WorkerResultAppend, now); err != nil {
		return err
	}
	observed, observedErr := time.Parse(time.RFC3339Nano, string(e.ObservedAt))
	ended, endedErr := time.Parse(time.RFC3339Nano, string(request.RunEndedAt))
	reset, resetErr := time.Parse(time.RFC3339Nano, string(e.ResetsAt))
	if e.Schema != "laneboss.usage-window.v2" || !launchID(e.ID) || e.Target != request.Target || e.LaunchID != request.LaunchID || e.OperationID != request.OperationID ||
		e.ProfileGrantID != request.ProfileGrantID || e.ProfileID != request.ProfileID || e.Provider != request.Provider || e.Provider == "" ||
		e.AdapterVersion != request.AdapterVersion || e.AdapterVersion == "" || e.Executable != request.Executable || !launchExecutable(e.Executable) ||
		e.RuntimeManifest != request.RuntimeManifest || e.RuntimeManifest != producer.Lease.RuntimeManifest ||
		producer.Lease.Kind != "usage" || producer.Lease.Target != request.Target || producer.Lease.OperationID != request.OperationID ||
		e.WorkerLeaseID != producer.Lease.ID || e.ProducerID != producer.Record.Actor.ID || e.ProducerGeneration != producer.Peer.ProcessGeneration || e.BootID != producer.BootID ||
		observedErr != nil || endedErr != nil || resetErr != nil || observed.Before(ended) || observed.After(now) || now.Sub(observed) > 30*time.Second || !reset.After(observed) ||
		math.IsNaN(e.UsedPercent) || math.IsInf(e.UsedPercent, 0) || e.UsedPercent < 100 || e.Window == "" || e.ExitCode != 0 ||
		!launchBlob(e.Raw, "usage_raw") || e.Raw.Bytes > MaxFrameBytes || e.Row < 1 {
		return launchInvalid("usage limit lacks fresh outside from-profile exhaustion")
	}
	return nil
}

// The source resolves vendorProfile from protected profile enrollment. Raw
// names stay in private vendor bytes, not in lane events. No guessed JSON shape.
func ValidateUsageSource(e UsageWindowEvidence, raw []byte, vendorProfile string) error {
	sum := sha256.Sum256(raw)
	reader := csv.NewReader(strings.NewReader(string(raw)))
	reader.Comma, reader.FieldsPerRecord = '\t', 5
	rows, err := reader.ReadAll()
	if err != nil || int64(len(raw)) != e.Raw.Bytes || Digest(hex.EncodeToString(sum[:])) != e.Raw.SHA256 ||
		len(raw) > MaxFrameBytes || e.Raw.Class != "usage_raw" || e.ExitCode != 0 ||
		len(rows) < 2 || strings.Join(rows[0], "\t") != "PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC" || e.Row < 1 || e.Row >= len(rows) || vendorProfile == "" {
		return launchInvalid("usage source differs from pinned vendor TSV bytes")
	}
	plans := map[string]string{}
	for _, record := range rows[1:] {
		used, usageErr := strconv.ParseFloat(record[3], 64)
		_, resetErr := time.Parse(time.RFC3339Nano, record[4])
		unknown := record[4] == "" || record[4] == "unknown" || record[4] == "-" || record[4] == "—"
		if record[0] == "" || record[1] == "" || record[2] == "" || usageErr != nil || math.IsNaN(used) || math.IsInf(used, 0) || used < 0 ||
			!unknown && resetErr != nil || plans[record[0]] != "" && plans[record[0]] != record[1] {
			return launchInvalid("usage command contains invalid or conflicting vendor rows")
		}
		plans[record[0]] = record[1]
	}
	row := rows[e.Row]
	used, usedErr := strconv.ParseFloat(row[3], 64)
	reset, resetErr := time.Parse(time.RFC3339Nano, row[4])
	expected, expectedErr := time.Parse(time.RFC3339Nano, string(e.ResetsAt))
	if row[0] != vendorProfile || row[1] == "" || row[2] != e.Window || usedErr != nil || math.IsNaN(used) || math.IsInf(used, 0) ||
		used != e.UsedPercent || resetErr != nil || expectedErr != nil || !reset.Equal(expected) {
		return launchInvalid("usage window fields differ from actual vendor row")
	}
	return nil
}
