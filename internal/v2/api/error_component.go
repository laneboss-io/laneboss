package api

import "errors"

// WithErrorComponent carries a closed diagnostic label inside this process.
// It is deliberately absent from JSON and cannot supply execution authority.
func WithErrorComponent(cause *Error, component string) *Error {
	if cause == nil {
		return nil
	}
	copy := *cause
	switch component {
	case "store_scope", "store_read_view", "store_read_connection", "store_object_view",
		"store_object", "store_projection", "store_lane", "store_launch", "store_launch_plan", "store_worker",
		"store_materialization", "store_grants", "store_policy", "store_source", "store_template", "store_guidance",
		"lifecycle_authorize", "service_authorize", "templates_scope", "secrets_scope", "secrets_worker":
		copy.component = component
	default:
		copy.component = "dependency"
	}
	return &copy
}

// ErrorComponent returns fixed words only. A remote error has no private
// location, so its closed owning component is the narrowest known diagnostic.
func ErrorComponent(err error) string {
	var cause *Error
	if !errors.As(err, &cause) || cause == nil {
		return "dependency"
	}
	if cause.component != "" {
		return cause.component
	}
	switch cause.Owner {
	case "lb-v2-integrate":
		return "integrate"
	case "lb-v2-linux":
		return "isolation_linux"
	case "lb-v2-darwin":
		return "isolation_darwin"
	case "lb-v2-service":
		return "service"
	case "lb-v2-lifecycle":
		return "lifecycle_authorize"
	case "lb-v2-grants":
		return "grants"
	case "lb-v2-secrets":
		return "secrets"
	case "lb-v2-templates":
		return "templates"
	case "lb-v2-admin":
		return "admin"
	case "lb-v2-identity":
		return "identity"
	case "lb-v2-guidance":
		return "guidance"
	case "lb-v2-codex", "lb-v2-claudock":
		return "runner"
	default:
		return "dependency"
	}
}
