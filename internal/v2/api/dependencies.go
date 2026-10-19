package api

import "reflect"

// RequireDependencies validates installed graph inputs without claiming that
// optional operation-specific capabilities have been enrolled or executed.
func RequireDependencies(owner string, values ...any) error {
	for _, value := range values {
		missing := value == nil
		if !missing {
			switch v := reflect.ValueOf(value); v.Kind() {
			case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
				missing = v.IsNil()
			}
		}
		if missing {
			return &Error{Code: CodePrerequisite, Owner: owner,
				Message: "installed component dependency is missing",
				Instead: "Wire every required installed dependency before service startup."}
		}
	}
	return nil
}
