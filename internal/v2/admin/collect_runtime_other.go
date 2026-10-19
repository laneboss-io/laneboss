//go:build !linux

package admin

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) ReadCleanupRuntime(context.Context, api.BlobRef) (api.CleanupObject, error) {
	return api.CleanupObject{}, failure(api.CodeUnsupported, "protected cleanup runtime measurements require Linux")
}

func (s *Service) ReadCleanupRuntimeManifest(context.Context) (api.BlobRef, api.RuntimeManifest, error) {
	return api.BlobRef{}, api.RuntimeManifest{}, failure(api.CodeUnsupported, "protected cleanup runtime measurements require Linux")
}
