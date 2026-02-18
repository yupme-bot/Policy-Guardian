package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"
)

// Deterministic canonical JSON writer compatible with RFC 8785 (JCS) for typical JSON.
// v0.1 enforcement:
//   - integers only (no floats / exponent)
//   - omit optional fields (never null)
// This build preserves UTF-8 strings as-is (valid UTF-8 required).
func CanonicalizeJSON(input []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return CanonicalizeValue(v)
}

func CanonicalizeValue(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeValue(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		return errors.New("null is not allowed (omit absent fields)")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		s := x.String()
		if strings.ContainsAny(s, ".eE") {
			return errors.New("floats/exponents are not allowed")
		}
		if len(s) == 0 || s[0] == '+' {
			return errors.New("invalid number")
		}
		buf.WriteString(s)
	case float64:
		return errors.New("floats are not allowed")
	case string:
		if !utf8.ValidString(x) {
			return errors.New("invalid utf-8 string")
		}
		enc, _ := json.Marshal(x)
		buf.Write(enc)
	case []any:
		buf.WriteByte('[')
		for i, it := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeValue(buf, it); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k, vv := range x {
			if vv == nil {
				return errors.New("null is not allowed (omit absent fields)")
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if !utf8.ValidString(k) {
				return errors.New("invalid utf-8 key")
			}
			kenc, _ := json.Marshal(k)
			buf.Write(kenc)
			buf.WriteByte(':')
			if err := writeValue(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		raw, err := json.Marshal(x)
		if err != nil {
			return err
		}
		return writeValueFromJSON(buf, raw)
	}
	return nil
}

func writeValueFromJSON(buf *bytes.Buffer, raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return err
	}
	return writeValue(buf, v)
}
