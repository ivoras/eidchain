package chain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// StrictUnmarshal decodes JSON into v and refuses everything that would give one
// value several encodings or let two parsers read a document differently:
//
//   - duplicate object keys (Go's decoder keeps the last, other parsers the first),
//   - field names that only match case-insensitively ("HEIGHT" for "height"),
//   - unknown fields, trailing data after the value,
//   - nesting deeper than maxJSONDepth. The walk is recursive and a Go stack
//     overflow cannot be recovered from, so depth must be bounded before the
//     input size is: a 16 MiB body of "[" would otherwise kill the process.
//
// Block hashes are computed from the parsed value, so none of these could forge
// a block, but a second implementation might read such a document differently.
func StrictUnmarshal(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := walk(dec, reflect.TypeOf(v), 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after JSON value")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

// maxJSONDepth is far deeper than any document this program defines.
const maxJSONDepth = 32

// walk follows the token stream together with the Go type being decoded.
func walk(dec *json.Decoder, t reflect.Type, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("JSON is nested deeper than %d levels", maxJSONDepth)
	}
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // a scalar
	}
	switch delim {
	case '{':
		var fields map[string]reflect.Type
		var elem reflect.Type
		structured := false
		if t != nil {
			switch t.Kind() {
			case reflect.Struct:
				fields, structured = structFields(t), true
			case reflect.Map:
				elem = t.Elem()
			}
		}
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key := kt.(string)
			if seen[key] {
				return fmt.Errorf("duplicate key %q", key)
			}
			seen[key] = true
			ft := elem
			if structured {
				var found bool
				if ft, found = fields[key]; !found {
					return fmt.Errorf("unknown field %q (field names are case-sensitive)", key)
				}
			}
			if err := walk(dec, ft, depth+1); err != nil {
				return err
			}
		}
		_, err = dec.Token() // '}'
		return err
	case '[':
		var et reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			et = t.Elem()
		}
		for dec.More() {
			if err := walk(dec, et, depth+1); err != nil {
				return err
			}
		}
		_, err = dec.Token() // ']'
		return err
	}
	return nil
}

// structFields maps each exact JSON name of a struct to its field type.
func structFields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		switch {
		case name == "-":
			continue
		case name == "" && f.Anonymous && f.Type.Kind() == reflect.Struct:
			for k, v := range structFields(f.Type) {
				out[k] = v
			}
			continue
		case name == "":
			name = f.Name
		}
		out[name] = f.Type
	}
	return out
}

// CheckPayloadJSON requires s to be one JSON object that every parser reads the
// same way: no duplicate keys, and no keys that differ only in case, at any
// level. This is the text people sign, so it is where ambiguity matters most:
// a record must not display as one message here and another elsewhere.
func CheckPayloadJSON(s string) error {
	dec := json.NewDecoder(strings.NewReader(s))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return errors.New("payload is not a JSON object")
	}
	if err := walkPayload(dec, '{', 1); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the JSON object")
	}
	return nil
}

// walkPayload consumes a container whose opening delimiter was already read.
func walkPayload(dec *json.Decoder, open json.Delim, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("JSON is nested deeper than %d levels", maxJSONDepth)
	}
	seen := map[string]bool{}
	for dec.More() {
		if open == '{' {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			// ToUpper then ToLower folds what encoding/json folds, such as the Kelvin sign.
			key := strings.ToLower(strings.ToUpper(kt.(string)))
			if seen[key] {
				return fmt.Errorf("duplicate or case-variant key %q", kt)
			}
			seen[key] = true
		}
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			if err := walkPayload(dec, d, depth+1); err != nil {
				return err
			}
		}
	}
	_, err := dec.Token() // the closing delimiter
	return err
}
