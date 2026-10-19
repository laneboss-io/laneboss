package approval

import (
	"path"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

const maxInteger = 1<<53 - 1

const route = "Have a current L6 stage the exact org source and derived diff, then obtain fresh per-change human confirmation."

func invalid(message string) *api.Error {
	return &api.Error{Code: api.CodeInvalid, Message: message, Instead: route, Owner: "lb-v2-approval"}
}

func forbidden(message string) *api.Error {
	return &api.Error{Code: api.CodeForbidden, Message: message, Instead: route, Owner: "lb-v2-approval"}
}

func integrity(message string) *api.Error {
	return &api.Error{Code: api.CodeIntegrity, Message: message,
		Instead: "Preserve the staged bytes and evidence for independent integrity review.", Owner: "lb-v2-approval"}
}

func conflict(message string) *api.Error {
	return &api.Error{Code: api.CodeConflict, Message: message, Instead: route, Owner: "lb-v2-approval"}
}

func validID(value api.ID) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' || char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}

func validDigest(value api.Digest) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func validGeneration(value api.Generation) bool {
	// An org change updates an enrolled baseline; it never creates an absent org.
	return value > 0 && value <= maxInteger
}

func validBlob(ref api.BlobRef) bool {
	return validID(ref.ID) && validDigest(ref.SHA256) && ref.Bytes >= 0 &&
		ref.Bytes <= api.MaxObjectBytes && validBlobClass(ref.Class)
}

func validBlobClass(class string) bool {
	switch class {
	case "task", "prompt", "report", "artifact", "capture", "transcript", "policy", "manifest",
		"judge_request", "judge_raw", "archive", "record":
		return true
	default:
		return false
	}
}

func validOwnership(ref api.BlobRef) bool {
	return validBlob(ref) && ref.Class == "manifest"
}

func validChangeStatus(status string) bool {
	switch status {
	case "proposed", "approved", "applied", "rejected":
		return true
	default:
		return false
	}
}

func validPath(value string) bool {
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) ||
		path.IsAbs(value) || value == "." || path.Clean(value) != value ||
		strings.ContainsAny(value, "\\:") || strings.ContainsFunc(value, unicode.IsControl) {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == ".." || component == "." || component == "" {
			return false
		}
	}
	return true
}

func validRenderer(renderer api.Executable) error {
	if !validID(renderer.ID) || !validDigest(renderer.SHA256) ||
		renderer.Version == "" || len(renderer.Version) > 128 ||
		!utf8.ValidString(renderer.Version) || strings.ContainsFunc(renderer.Version, unicode.IsControl) {
		return invalid("renderer must identify its exact artifact and version")
	}
	return nil
}

func normalizedFiles(files []api.ResourceDelta, allowEmpty bool) ([]api.ResourceDelta, error) {
	if files == nil || !allowEmpty && len(files) == 0 {
		return nil, invalid("resource deltas must be an array with source changes")
	}
	// The wire frame is the aggregate bound. No command or resource-kind list
	// determines authority; every org-relative source path follows D6.
	out := make([]api.ResourceDelta, len(files))
	for i, file := range files {
		if !validPath(file.Path) || file.Mode > 0777 {
			return nil, invalid("resource path or ordinary file mode is invalid")
		}
		switch file.Action {
		case "add":
			if file.BeforeSHA256 != "" || file.After == nil {
				return nil, invalid("add requires after bytes and no before hash")
			}
		case "replace":
			if !validDigest(file.BeforeSHA256) || file.After == nil {
				return nil, invalid("replace requires before hash and after bytes")
			}
		case "delete":
			if !validDigest(file.BeforeSHA256) || file.After != nil {
				return nil, invalid("delete requires before hash and no after bytes")
			}
		default:
			return nil, invalid("resource action must be add, replace or delete")
		}
		if file.After != nil {
			if !validBlob(*file.After) {
				return nil, invalid("resource after bytes need a bounded committed blob")
			}
			copyRef := *file.After
			file.After = &copyRef
		}
		out[i] = file
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	if err := disjointFiles(out, nil); err != nil {
		return nil, err
	}
	return out, nil
}

func disjointFiles(first, second []api.ResourceDelta) error {
	paths := make(map[string]bool, len(first)+len(second))
	for _, group := range [][]api.ResourceDelta{first, second} {
		for _, file := range group {
			if paths[file.Path] {
				return invalid("source and derived paths must be unique")
			}
			paths[file.Path] = true
		}
	}
	for name := range paths {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if paths[parent] {
				return invalid("resource paths conflict as file and directory")
			}
		}
	}
	return nil
}

// ValidatePropose validates local input only. It does not attest source
// ownership, the current org generation or whether a blob has been committed.
func ValidatePropose(request api.ChangeProposeRequest) error {
	if !validID(request.OrgID) || !validGeneration(request.BaseGeneration) || !validBlob(request.Reason) {
		return invalid("proposal requires org, current base and retained reason")
	}
	_, err := normalizedFiles(request.Files, false)
	return err
}

func ValidateGet(request api.ChangeGetRequest) error {
	if !validID(request.ChangeID) {
		return invalid("a valid change ID is required")
	}
	return nil
}

func ValidateApprove(request api.ChangeApproveRequest) error {
	if !validID(request.ChangeID) || !validDigest(request.ManifestSHA256) || !validGeneration(request.BaseGeneration) {
		return invalid("approval requires change ID, exact manifest and base")
	}
	return nil
}

func ValidateApply(request api.ChangeApplyRequest) error {
	if !validID(request.ChangeID) || !validID(request.ApprovalID) || !validGeneration(request.ExpectedGeneration) {
		return invalid("application requires change ID, approval ID and base")
	}
	return nil
}

// ValidateChange checks a retained ChangeRequest without interpreting its
// status as a receipt or treating expiry as a reason to hide history.
func ValidateChange(change api.ChangeRequest) error {
	if !validID(api.ID(change.Config)) || !validBlob(change.Reason) || !validOwnership(change.OwnershipManifest) ||
		change.SourceSnapshot.OrgID != change.OrgID || change.SourceSnapshot.Generation != change.BaseGeneration ||
		!validDigest(change.SourceSnapshot.ManifestSHA256) {
		return integrity("retained change lacks its configuration, reason or approved source provenance")
	}
	if !validID(change.ID) || change.Requester.Kind != "lane" ||
		change.Requester.Level != 6 || !validID(change.Requester.ID) ||
		!validID(change.Requester.LifeID) || change.Requester.Role == "" ||
		!validBlob(change.Diff) || !validDigest(change.ManifestSHA256) ||
		!validChangeStatus(change.Status) {
		return integrity("retained change is missing its identity, diff or provenance")
	}
	created, err := timestamp(change.CreatedAt)
	if err != nil {
		return integrity("retained change creation time is invalid")
	}
	expires, err := timestamp(change.ExpiresAt)
	if err != nil || !expires.After(created) || expires.Sub(created) > 24*time.Hour {
		return integrity("retained change lifetime is invalid")
	}
	digest, err := ManifestDigest(change)
	if err != nil || digest != change.ManifestSHA256 {
		return integrity("retained change manifest does not match its exact deltas")
	}
	files, err := normalizedFiles(change.Files, false)
	if err != nil {
		return integrity("retained source deltas are invalid")
	}
	derived, err := normalizedFiles(change.Derived, true)
	if err != nil {
		return integrity("retained derived deltas are invalid")
	}
	for i := range files {
		if files[i].Path != change.Files[i].Path {
			return integrity("retained source deltas are not sorted")
		}
	}
	for i := range derived {
		if derived[i].Path != change.Derived[i].Path {
			return integrity("retained derived deltas are not sorted")
		}
	}
	return nil
}

// ValidateApproval checks receipt structure and time bounds. Only the identity
// and atomic store boundary can verify the key and nonce; shape is no proof.
func ValidateApproval(approval api.ChangeApproval) error {
	if !validID(approval.ID) || !validID(approval.ChangeID) ||
		!validID(approval.RequesterLifeID) || !validID(approval.ApproverKeyID) ||
		!validID(approval.NonceID) || !validDigest(approval.ManifestSHA256) ||
		!validGeneration(approval.BaseGeneration) {
		return integrity("approval receipt lacks exact change or verified provenance references")
	}
	approved, err := timestamp(approval.ApprovedAt)
	if err != nil {
		return integrity("approval receipt time is invalid")
	}
	expires, err := timestamp(approval.ExpiresAt)
	if err != nil || !expires.After(approved) || expires.Sub(approved) > 10*time.Minute {
		return integrity("approval receipt exceeds the permitted lifetime")
	}
	return nil
}

func ValidateReceipt(receipt api.ChangeReceipt) error {
	if !validID(receipt.ID) || !validID(receipt.ChangeID) || !validID(receipt.ApprovalID) ||
		!validDigest(receipt.ManifestSHA256) || !validGeneration(receipt.OldGeneration) ||
		!validGeneration(receipt.NewGeneration) || receipt.NewGeneration != receipt.OldGeneration+1 {
		return integrity("application receipt has invalid identity, hash or generation")
	}
	if _, err := timestamp(receipt.AppliedAt); err != nil {
		return integrity("application receipt time is invalid")
	}
	return nil
}

func timestamp(value api.Timestamp) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, string(value))
	if err != nil || !strings.HasSuffix(string(value), "Z") ||
		parsed.Format(time.RFC3339Nano) != string(value) {
		return time.Time{}, invalid("timestamp must be canonical RFC3339Nano UTC")
	}
	return parsed, nil
}

func approvalMethod(method api.Method) bool {
	switch method {
	case "org.change.propose", "org.change.get", "org.change.approve", "org.change.apply":
		return true
	default:
		return false
	}
}
