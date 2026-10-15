package loggen

import (
	"fmt"
	"net/url"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Field is a typed key/value pair. It is an alias of [zap.Field], so
// fields built with zap's own constructors work everywhere loggen accepts
// a Field. The helpers below cover the common cases without importing zap.
type Field = zap.Field

// String constructs a field with a string value.
func String(key, val string) Field { return zap.String(key, val) }

// Strings constructs a field with a []string value.
func Strings(key string, val []string) Field { return zap.Strings(key, val) }

// Int constructs a field with an int value.
func Int(key string, val int) Field { return zap.Int(key, val) }

// Int64 constructs a field with an int64 value.
func Int64(key string, val int64) Field { return zap.Int64(key, val) }

// Uint64 constructs a field with a uint64 value.
func Uint64(key string, val uint64) Field { return zap.Uint64(key, val) }

// Float64 constructs a field with a float64 value.
func Float64(key string, val float64) Field { return zap.Float64(key, val) }

// Bool constructs a field with a bool value.
func Bool(key string, val bool) Field { return zap.Bool(key, val) }

// Duration constructs a field with a time.Duration value.
func Duration(key string, val time.Duration) Field { return zap.Duration(key, val) }

// Time constructs a field with a time.Time value.
func Time(key string, val time.Time) Field { return zap.Time(key, val) }

// Err constructs a field with key "error" (like zap.Error). The error
// message is logged as-is and is not scanned for secrets.
func Err(err error) Field { return zap.Error(err) }

// NamedError constructs an error field with a custom key.
func NamedError(key string, err error) Field { return zap.NamedError(key, err) }

// Stringer constructs a field from a fmt.Stringer, evaluated lazily.
func Stringer(key string, val fmt.Stringer) Field { return zap.Stringer(key, val) }

// Object constructs a field from a zapcore.ObjectMarshaler. Nested keys
// are redacted.
func Object(key string, val zapcore.ObjectMarshaler) Field { return zap.Object(key, val) }

// Array constructs a field from a zapcore.ArrayMarshaler.
func Array(key string, val zapcore.ArrayMarshaler) Field { return zap.Array(key, val) }

// Dict constructs a nested object field from other fields. Nested keys are
// redacted.
func Dict(key string, val ...Field) Field { return zap.Dict(key, val...) }

// Namespace opens a nested object; all later fields on the entry or logger
// go inside it. If key is sensitive, every field inside is redacted.
func Namespace(key string) Field { return zap.Namespace(key) }

// Any picks the best field constructor for val. Prefer the typed helpers on
// hot paths: Any falls back to reflection for unknown types, and arbitrary
// structs are not walked for redaction (see the package documentation).
func Any(key string, val any) Field { return zap.Any(key, val) }

// URL logs u as a string with its password and the values of sensitive
// query and fragment parameters (token, api_key, ...) redacted. zap.Any and
// zap.Stringer with a *url.URL are redacted the same way; this helper just
// makes the intent explicit. Without redaction (RedactionConfig.Disabled)
// the URL is logged as is.
func URL(key string, u *url.URL) Field { return zap.Stringer(key, u) }
