package rscan

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// NativeReleaseScan crosses only the authenticated root-helper/broker stream.
// It contains verdicts, redacted native finding paths and original metadata,
// never credential material or a caller-selected path. Public/service metadata
// endpoints do not provide it.
type NativeReleaseScan struct {
	Authority api.CredentialProjectionAuthority
	Cause     api.InternalIntent
	Scan      APIKeyScanResult
}

type nativeScanKey struct{}

func WithNativeReleaseScan(ctx context.Context, scan *NativeReleaseScan) context.Context {
	return context.WithValue(ctx, nativeScanKey{}, scan)
}

func NativeReleaseScanFromContext(ctx context.Context) *NativeReleaseScan {
	scan, _ := ctx.Value(nativeScanKey{}).(*NativeReleaseScan)
	return scan
}

func ReadNativeReleaseScan(ctx context.Context, authority api.CredentialProjectionAuthority, material api.SecretMaterial) (APIKeyScanResult, error) {
	scan := NativeReleaseScanFromContext(ctx)
	if err := ctx.Err(); err != nil {
		return APIKeyScanResult{}, err
	}
	if scan == nil || !reflect.DeepEqual(scan.Authority, authority) || scan.Cause.Target != authority.Request.Prepared.Target ||
		scan.Cause.Kind != api.InternalHelperRelease && scan.Cause.Kind != api.InternalHelperStop && scan.Cause.Kind != api.InternalHelperAbort ||
		len(material.Bytes) < 8 || len(material.Bytes) > 4096 {
		return APIKeyScanResult{}, &api.Error{Code: api.CodeForbidden, Owner: "lb-v2-secrets", Message: "API key release has no exact native scan"}
	}
	return scan.Scan.Redacted(material.Bytes), nil
}
