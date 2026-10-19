package lifecycle

import (
	"context"
	"crypto/sha256"
	"fmt"
	"regexp"

	"laneboss.io/laneboss/internal/v2/api"
)

var vendorSessionUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func (execution *planExecution) runnerSession(ctx context.Context, inputs api.LaunchInputs, data api.LaunchData) (api.Session, error) {
	s, r, input := execution.service, execution.record.Reservation, execution.input
	session := api.Session{ID: launchObjectID(r.ID, "session"), Driver: input.driver, HomeID: data.Home.Home.ID,
		HistoryID: data.Home.Home.HistoryID, LogicalCWD: data.Workspace.LogicalCWD}
	if input.previous != nil {
		previous, err := s.deps.Store.Lane(ctx, execution.scope, input.previous.Record.Target)
		if err != nil {
			return api.Session{}, failure(err)
		}
		session = previous.Session
	}
	if r.Mode == "adopt" {
		var request api.AdoptRequest
		if api.DecodeObject(input.request.Params, &request) != nil {
			return api.Session{}, integrity("retained adoption request is invalid")
		}
		raw, err := s.readBlob(ctx, execution.scope, request.ImportManifest)
		if err != nil {
			return api.Session{}, err
		}
		var manifest api.AdoptionManifest
		if api.DecodeObject(raw, &manifest) != nil || manifest.Session.Driver != input.driver || !validSession(manifest.Session) ||
			manifest.Workspace.ProjectID != data.Workspace.ProjectID {
			return api.Session{}, integrity("adopted history does not match the worker's private home")
		}
		// The helper owns the new storage; only the imported conversation's
		// vendor identity survives adoption.
		session.VendorID, session.VendorVersion = manifest.Session.VendorID, manifest.Session.VendorVersion
	}
	if input.driver != api.DriverClaudock {
		return session, nil
	}
	raw, err := s.readBlob(ctx, execution.scope, inputs.Sources.Runtime.Manifest)
	if err != nil {
		return api.Session{}, err
	}
	var manifest api.RuntimeManifest
	if api.DecodeObject(raw, &manifest) != nil {
		return api.Session{}, problem(api.CodePrerequisite, "installed session runtime cannot decode", "Install a valid pinned runtime enrollment.")
	}
	vendor, err := api.RuntimeSessionExecutable(inputs.Sources.Runtime, manifest)
	if err != nil {
		return api.Session{}, err
	}
	if input.previous != nil || r.Mode == "adopt" {
		if !vendorSessionUUID.MatchString(session.VendorID) || session.VendorVersion != vendor.Version {
			return api.Session{}, problem(api.CodePrerequisite, "retained session differs from the enrolled vendor", "Restore the exact enrolled vendor for this retained history.")
		}
		return session, nil
	}
	// A deterministic RFC 9562 version-8 UUID binds the new conversation to
	// its service-owned logical session and exact installed vendor pin. Replay
	// reproduces it without asking a runner or manufacturing another session.
	id := sha256.Sum256([]byte("laneboss.vendor-session.v1\x00" + string(session.ID) + "\x00" +
		string(vendor.ID) + "\x00" + string(vendor.SHA256) + "\x00" + vendor.Version))
	id[6], id[8] = id[6]&0x0f|0x80, id[8]&0x3f|0x80
	session.VendorID = fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:16])
	session.VendorVersion = vendor.Version
	return session, nil
}
