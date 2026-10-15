package loggen

import (
	"errors"
	"fmt"
	"io"
	"time"

	"go.uber.org/zap/zapcore"
)

// Level is a logging severity. It is an alias of [zapcore.Level], so Zap
// levels can be used directly.
type Level = zapcore.Level

// Supported levels, from least to most severe.
const (
	DebugLevel  = zapcore.DebugLevel
	InfoLevel   = zapcore.InfoLevel
	WarnLevel   = zapcore.WarnLevel
	ErrorLevel  = zapcore.ErrorLevel
	DPanicLevel = zapcore.DPanicLevel
	PanicLevel  = zapcore.PanicLevel
	FatalLevel  = zapcore.FatalLevel
)

// Format selects the output encoding.
type Format string

const (
	// FormatJSON writes one JSON object per entry using Zap's JSON encoder.
	FormatJSON Format = "json"
	// FormatConsole writes human-readable lines using Zap's console encoder.
	FormatConsole Format = "console"
)

// Configuration errors returned (wrapped) by [Config.Validate] and [New].
// Test for them with [errors.Is].
var (
	ErrInvalidFormat    = errors.New("loggen: invalid format")
	ErrInvalidLevel     = errors.New("loggen: invalid level")
	ErrInvalidSampling  = errors.New("loggen: invalid sampling config")
	ErrInvalidRedaction = errors.New("loggen: invalid redaction config")
)

// ParseLevel parses a level name such as "debug", "info", "warn" or "error"
// (case-insensitive).
func ParseLevel(s string) (Level, error) {
	lvl, err := zapcore.ParseLevel(s)
	if err != nil {
		return lvl, fmt.Errorf("%w: %q", ErrInvalidLevel, s)
	}
	return lvl, nil
}

// Config configures a [Logger]. The zero value is valid: JSON output to
// stderr at Info level, with caller, error stack traces and redaction
// enabled, and no sampling.
type Config struct {
	// Service, Environment and Version are attached to every entry as
	// "service", "env" and "version" when non-empty.
	Service     string
	Environment string
	Version     string

	// Level is the minimum enabled level. The zero value is InfoLevel.
	// It can be changed at runtime with [Logger.SetLevel].
	Level Level

	// Format is the output encoding. Empty means FormatJSON, or
	// FormatConsole when Development is set.
	Format Format

	// Development switches to Zap's development encoder config (ISO8601
	// times, capitalized levels), stack traces from Warn, and
	// zap.Development (DPanic panics).
	Development bool

	// Output receives log entries. Nil means os.Stderr. Writes are
	// serialized with a mutex, so any io.Writer is safe to use. If it
	// implements Sync() error, [Logger.Sync] calls it.
	Output io.Writer
	// ErrorOutput receives Zap's internal errors (for example a failed
	// write). Nil means os.Stderr.
	ErrorOutput io.Writer

	// DisableCaller omits the "caller" field.
	DisableCaller bool
	// DisableStacktrace omits automatic stack traces on Error (or Warn in
	// development).
	DisableStacktrace bool

	// Sampling, when non-nil, enables Zap's sampler. See [SamplingConfig].
	Sampling *SamplingConfig

	// Redaction controls sensitive-field redaction. It is on by default.
	Redaction RedactionConfig
}

// SamplingConfig limits repeated entries: within each Tick, the first
// Initial entries with a given level and message are logged, then every
// Thereafter-th. Thereafter 0 drops all entries past Initial.
type SamplingConfig struct {
	Tick       time.Duration
	Initial    int
	Thereafter int
}

// RedactionConfig controls which fields are redacted. Keys are matched
// case-insensitively after removing '-', '_', '.' and spaces, so
// "access_token", "AccessToken" and "Access-Token" are the same key.
type RedactionConfig struct {
	// Disabled turns redaction off entirely.
	Disabled bool
	// Keys are additional exact key names to redact.
	Keys []string
	// Substrings redact any key containing one of them.
	Substrings []string
	// Suffixes redact any key ending with one of them.
	Suffixes []string
	// ReplaceDefaults makes Keys, Substrings and Suffixes replace the
	// built-in lists ([DefaultSensitiveKeys], [DefaultSensitiveSubstrings],
	// [DefaultSensitiveSuffixes]) instead of extending them.
	ReplaceDefaults bool
	// RedactPII also redacts common personal-data keys ([PIIKeys],
	// [PIISubstrings], [PIISuffixes]): card numbers, CVV, SSN, IBAN, date
	// of birth.
	RedactPII bool
	// Placeholder replaces redacted values. Empty means "[REDACTED]".
	Placeholder string
}

// ProductionConfig returns Zap's production defaults: JSON, Info level,
// caller, stack traces on Error, and sampling of 100 entries per second per
// level and message, then every 100th.
//
// Sampling drops repeated entries, so under load (or a deliberate flood) most
// repetitions of an application message are dropped. Access-log entries from
// [Logger.Middleware] are never sampled. Set Sampling to nil if every
// application entry must be kept.
func ProductionConfig(service string) Config {
	return Config{
		Service:     service,
		Environment: "production",
		Level:       InfoLevel,
		Format:      FormatJSON,
		Sampling:    &SamplingConfig{Tick: time.Second, Initial: 100, Thereafter: 100},
	}
}

// DevelopmentConfig returns Zap's development defaults: console output,
// Debug level, caller, stack traces on Warn, no sampling.
func DevelopmentConfig(service string) Config {
	return Config{
		Service:     service,
		Environment: "development",
		Level:       DebugLevel,
		Format:      FormatConsole,
		Development: true,
	}
}

// Validate reports configuration errors. [New] calls it.
func (c Config) Validate() error {
	switch c.Format {
	case "", FormatJSON, FormatConsole:
	default:
		return fmt.Errorf("%w: %q (want %q or %q)", ErrInvalidFormat, c.Format, FormatJSON, FormatConsole)
	}
	if c.Level < DebugLevel || c.Level > FatalLevel {
		return fmt.Errorf("%w: %d", ErrInvalidLevel, int8(c.Level))
	}
	if s := c.Sampling; s != nil {
		if s.Tick <= 0 || s.Initial <= 0 || s.Thereafter < 0 {
			return fmt.Errorf("%w: tick and initial must be positive, thereafter non-negative", ErrInvalidSampling)
		}
	}
	r := c.Redaction
	if r.Disabled {
		return nil
	}
	for _, k := range r.Keys {
		if normalizeKey(k) == "" {
			return fmt.Errorf("%w: empty key %q", ErrInvalidRedaction, k)
		}
	}
	for _, s := range r.Substrings {
		if normalizeKey(s) == "" {
			return fmt.Errorf("%w: empty substring %q", ErrInvalidRedaction, s)
		}
	}
	for _, s := range r.Suffixes {
		if normalizeKey(s) == "" {
			return fmt.Errorf("%w: empty suffix %q", ErrInvalidRedaction, s)
		}
	}
	if r.ReplaceDefaults && !r.RedactPII && len(r.Keys) == 0 && len(r.Substrings) == 0 && len(r.Suffixes) == 0 {
		return fmt.Errorf("%w: ReplaceDefaults with no keys redacts nothing; set Disabled instead", ErrInvalidRedaction)
	}
	return nil
}
