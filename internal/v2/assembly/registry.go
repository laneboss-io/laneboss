package assembly

import (
	"errors"
	"reflect"
	"sort"

	"laneboss.io/laneboss/internal/v2/api"
)

type ownedModule struct {
	owner  string
	module api.Module
}

type catalogRegistrar struct {
	target  api.Registrar
	owner   string
	seen    map[api.Method]bool
	streams map[api.Method]bool
	failure error
}

func (r *catalogRegistrar) claim(method api.Method) error {
	spec, exists := api.Methods[method]
	if !exists || spec.Owner != r.owner || r.seen[method] {
		return &api.Error{Code: api.CodeIntegrity, Message: "duplicate, unknown or incorrectly owned RPC registration", Instead: "Repair the named module against the frozen catalog.", Owner: r.owner}
	}
	r.seen[method] = true
	return nil
}

func (r *catalogRegistrar) Register(method api.Method, handler api.Handler) (err error) {
	defer func() { r.rememberFailure(err) }()
	if handler == nil {
		return installError("nil typed RPC handler")
	}
	if err := r.claim(method); err != nil {
		return err
	}
	return r.target.Register(method, handler)
}

func (r *catalogRegistrar) RegisterStream(method api.Method, handler api.StreamHandler) (err error) {
	defer func() { r.rememberFailure(err) }()
	if handler == nil {
		return installError("nil typed stream handler")
	}
	if method != "event.tail" && method != "lane.attach" {
		return installError("method is not a frozen stream")
	}
	if r.streams[method] {
		return installError("duplicate typed stream handler")
	}
	// Follow/attach share their initial typed response handler. A separate
	// stream registration supplements it, and cannot replace that handler.
	spec, exists := api.Methods[method]
	if !exists || spec.Owner != r.owner {
		return installError("incorrectly owned stream registration")
	}
	if err := r.target.RegisterStream(method, handler); err != nil {
		return err
	}
	r.streams[method] = true
	return nil
}

func (r *catalogRegistrar) rememberFailure(err error) {
	if err != nil && r.failure == nil {
		r.failure = err
	}
}

func registerModules(target api.Registrar, modules []ownedModule) error {
	if nilRegistration(target) {
		return installError("RPC registrar is missing")
	}
	// Stage the complete graph before touching the transport. An incomplete
	// owner must not expose the successful subset it happened to register.
	all := newModuleRoutes()
	owners := make(map[string]bool)
	methods := catalogMethods("")
	for _, entry := range modules {
		owned := catalogMethods(entry.owner)
		if entry.owner == "" || len(owned) == 0 || owners[entry.owner] {
			return installError("invalid or duplicate module owner")
		}
		owners[entry.owner] = true
		routes := newModuleRoutes()
		registry := &catalogRegistrar{target: routes, owner: entry.owner,
			seen: make(map[api.Method]bool), streams: make(map[api.Method]bool)}
		var registrationErr error
		if !nilRegistration(entry.module) {
			registrationErr = entry.module.Register(registry)
		}
		if registry.failure != nil {
			return registry.failure
		}
		if registrationErr != nil {
			var typed *api.Error
			if !errors.As(registrationErr, &typed) || typed.Code != api.CodeNotImplemented || typed.Owner != entry.owner {
				return registrationErr
			}
		}
		missing := api.Method("")
		for _, method := range owned {
			if routes.handlers[method] == nil || streamMethod(method) && routes.streams[method] == nil {
				missing = method
				break
			}
		}
		if registrationErr != nil || missing != "" {
			if missing == "" {
				missing = owned[0]
			}
			var err error
			routes, err = unavailableRoutes(entry.owner, owned, missing)
			if err != nil {
				return err
			}
		}
		for method, handler := range routes.handlers {
			all.handlers[method] = handler
		}
		for method, handler := range routes.streams {
			all.streams[method] = handler
		}
	}
	// Omitted owners are a composition mistake, even in development. Only an
	// explicitly listed unready module may receive development refusal routes.
	for _, method := range methods {
		if all.handlers[method] == nil {
			return missingHandler(method)
		}
	}
	for _, method := range methods {
		if err := target.Register(method, all.handlers[method]); err != nil {
			return err
		}
		if streamMethod(method) {
			if err := target.RegisterStream(method, all.streams[method]); err != nil {
				return err
			}
		}
	}
	return nil
}

func catalogMethods(owner string) []api.Method {
	var methods []api.Method
	for method, spec := range api.Methods {
		if owner == "" || spec.Owner == owner {
			methods = append(methods, method)
		}
	}
	sort.Slice(methods, func(i, j int) bool { return methods[i] < methods[j] })
	return methods
}

func missingHandler(method api.Method) error {
	return &api.Error{Code: api.CodeNotImplemented, Owner: api.Methods[method].Owner,
		Message: "required RPC handler is missing: " + string(method),
		Instead: "Finish the owning module " + "before starting the service."}
}

func streamMethod(method api.Method) bool {
	return method == "event.tail" || method == "lane.attach"
}

func nilRegistration(value any) bool {
	if value == nil {
		return true
	}
	switch reflected := reflect.ValueOf(value); reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	}
	return false
}

type moduleRoutes struct {
	handlers map[api.Method]api.Handler
	streams  map[api.Method]api.StreamHandler
}

func newModuleRoutes() *moduleRoutes {
	return &moduleRoutes{handlers: make(map[api.Method]api.Handler), streams: make(map[api.Method]api.StreamHandler)}
}

func (r *moduleRoutes) Register(method api.Method, handler api.Handler) error {
	r.handlers[method] = handler
	return nil
}

func (r *moduleRoutes) RegisterStream(method api.Method, handler api.StreamHandler) error {
	r.streams[method] = handler
	return nil
}
