package boxgcp

import (
	"strings"

	"laneboss.io/laneboss/internal/boxcore"
)

func localError(op, detail string, err error) *boxcore.Error {
	return boxcore.NewError(boxcore.KindOther, op, "", detail, err)
}

func detail(stderr string) string {
	text := strings.TrimSpace(stderr)
	text = strings.NewReplacer("\r", " ", "\n", " ").Replace(text)
	runes := []rune(text)
	if len(runes) > 300 {
		runes = runes[:300]
	}
	return string(runes)
}

func classify(op, stderr string) *boxcore.Error {
	text := strings.ToLower(stderr)
	has := func(s string) bool { return strings.Contains(text, strings.ToLower(s)) }
	kind := boxcore.KindOther
	switch {
	case has("ZONE_RESOURCE_POOL_EXHAUSTED"),
		has("does not have enough resources available"),
		has("is currently unavailable in the"):
		kind = boxcore.KindCapacity
	case has("QUOTA_EXCEEDED"), has("Quota '") && has("exceeded"):
		kind = boxcore.KindQuota
	case has("PERMISSION_DENIED"), has("Required '") && has("permission"),
		has("does not have permission"), has("HTTPError 403"),
		has("Failed to impersonate"), has("iam.serviceAccounts.getAccessToken"),
		has("insufficient authentication scopes"):
		kind = boxcore.KindDenied
	case has("was not found"), has("HTTPError 404"), has("notFound"):
		kind = boxcore.KindNotFound
	}
	code := ""
	for _, candidate := range []string{
		"ZONE_RESOURCE_POOL_EXHAUSTED", "QUOTA_EXCEEDED", "PERMISSION_DENIED",
	} {
		if has(candidate) {
			code = candidate
			break
		}
	}
	return boxcore.NewError(kind, op, code, detail(stderr), nil)
}
