package identity

import "laneboss.io/laneboss/internal/v2/api"

var _ api.EnrollmentValidator = (*Service)(nil)
var _ api.ConnectionInvalidationBinder = (*Service)(nil)
