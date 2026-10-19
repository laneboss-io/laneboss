package service

import "laneboss.io/laneboss/internal/v2/api"

var _ api.ConnectionInvalidator = (*Server)(nil)
var _ api.AdminEnrollment = (*Server)(nil)
var _ api.MaterializationControl = (*Server)(nil)
var _ api.WorkerBootstrap = (*Server)(nil)
