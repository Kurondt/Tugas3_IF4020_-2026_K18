package jsonx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"signer/internal/contract"
)

var (
	ErrFormat         = errors.New("invalid JSON format")
	ErrNotImplemented = contract.ErrNotImplemented
)

func Decode(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, ErrFormat
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, err := value(d, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrFormat
	}
	return v, nil
}

func value(d *json.Decoder, depth int) (any, error) {
	if depth > 128 {
		return nil, ErrFormat
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch t {
	case json.Delim('{'):
		m := map[string]any{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return nil, err
			}
			s, ok := k.(string)
			if !ok {
				return nil, ErrFormat
			}
			if _, exists := m[s]; exists {
				return nil, fmt.Errorf("duplicate field %q", s)
			}
			v, err := value(d, depth+1)
			if err != nil {
				return nil, err
			}
			m[s] = v
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, ErrFormat
		}
		return m, nil
	case json.Delim('['):
		a := []any{}
		for d.More() {
			v, err := value(d, depth+1)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, ErrFormat
		}
		return a, nil
	default:
		if _, ok := t.(json.Delim); ok {
			return nil, ErrFormat
		}
		return t, nil
	}
}

// Object requires exactly the named fields, including non-null values.
func Object(v any, fields ...string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != len(fields) {
		return nil, ErrFormat
	}
	for _, f := range fields {
		if v, ok := m[f]; !ok || v == nil {
			return nil, ErrFormat
		}
	}
	return m, nil
}

// Into validates exact fields and types against a concrete JSON struct. Decode
// must already have checked duplicates; this second pass rejects nulls in structs.
func Into(v any, out any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return ErrFormat
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return fmt.Errorf("%w: %v", ErrFormat, err)
	}
	return nil
}
