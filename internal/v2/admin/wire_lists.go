package admin

import (
	"encoding"
	"encoding/json"
	"reflect"
)

// EncodeWire is the encoder of V2's private helper and credential wires.
// json.Marshal writes a nil slice or map as null, and every strict decoder
// refuses null for a list or an object, so wireLists gives the value empty
// ones first. The decoders keep refusing null.
func EncodeWire(value any) ([]byte, error) {
	return json.Marshal(wireLists(value))
}

// wireLists returns value with every nil slice and nil map, at any depth
// through structs, pointers, arrays, slices, maps and interfaces, replaced by
// an empty one. The caller's value is never written: changed parts are
// copies. A nil []byte becomes empty, which encodes as the base64 "" that the
// decoder accepts (nil encodes as null, which it refuses); a non-nil []byte is
// kept as is. Nil pointers stay nil, and a type with its own JSON or text
// encoding (json.RawMessage, time.Time) is left to that encoding.
func wireLists(value any) any {
	if value == nil {
		return nil
	}
	normal, changed := wireListValue(reflect.ValueOf(value), 0)
	if !changed {
		return value
	}
	return normal.Interface()
}

var (
	wireJSONMarshaler = reflect.TypeFor[json.Marshaler]()
	wireTextMarshaler = reflect.TypeFor[encoding.TextMarshaler]()
)

// A cyclic value is left as is past this depth, so json.Marshal still
// reports its own cycle error instead of the walk never ending.
const wireListDepth = 1000

func wireOwnEncoding(t reflect.Type) bool {
	if t.Kind() == reflect.Interface {
		return false
	}
	pointer := reflect.PointerTo(t)
	return t.Implements(wireJSONMarshaler) || t.Implements(wireTextMarshaler) ||
		pointer.Implements(wireJSONMarshaler) || pointer.Implements(wireTextMarshaler)
}

func wireListValue(v reflect.Value, depth int) (reflect.Value, bool) {
	t := v.Type()
	if depth > wireListDepth || wireOwnEncoding(t) {
		return v, false
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return v, false
		}
		elem, changed := wireListValue(v.Elem(), depth+1)
		if !changed {
			return v, false
		}
		copied := reflect.New(t.Elem())
		copied.Elem().Set(elem)
		return copied, true
	case reflect.Interface:
		if v.IsNil() {
			return v, false
		}
		elem, changed := wireListValue(v.Elem(), depth+1)
		if !changed {
			return v, false
		}
		copied := reflect.New(t).Elem()
		copied.Set(elem)
		return copied, true
	case reflect.Struct:
		var copied reflect.Value
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if !field.IsExported() || field.Tag.Get("json") == "-" {
				continue
			}
			normal, changed := wireListValue(v.Field(i), depth+1)
			if !changed {
				continue
			}
			if !copied.IsValid() {
				copied = reflect.New(t).Elem()
				copied.Set(v)
			}
			copied.Field(i).Set(normal)
		}
		if !copied.IsValid() {
			return v, false
		}
		return copied, true
	case reflect.Slice:
		if v.IsNil() {
			return reflect.MakeSlice(t, 0, 0), true
		}
		if t.Elem().Kind() == reflect.Uint8 {
			return v, false
		}
		return wireListElements(v, depth)
	case reflect.Array:
		return wireListElements(v, depth)
	case reflect.Map:
		if v.IsNil() {
			return reflect.MakeMap(t), true
		}
		copied, changed := reflect.MakeMapWithSize(t, v.Len()), false
		entries := v.MapRange()
		for entries.Next() {
			normal, normalChanged := wireListValue(entries.Value(), depth+1)
			changed = changed || normalChanged
			copied.SetMapIndex(entries.Key(), normal)
		}
		if !changed {
			return v, false
		}
		return copied, true
	}
	return v, false
}

func wireListElements(v reflect.Value, depth int) (reflect.Value, bool) {
	var copied reflect.Value
	for i := 0; i < v.Len(); i++ {
		normal, changed := wireListValue(v.Index(i), depth+1)
		if !changed {
			continue
		}
		if !copied.IsValid() {
			if v.Kind() == reflect.Slice {
				copied = reflect.MakeSlice(v.Type(), v.Len(), v.Len())
				reflect.Copy(copied, v)
			} else {
				copied = reflect.New(v.Type()).Elem()
				copied.Set(v)
			}
		}
		copied.Index(i).Set(normal)
	}
	if !copied.IsValid() {
		return v, false
	}
	return copied, true
}
