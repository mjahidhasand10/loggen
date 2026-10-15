package loggen

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

// Logger is a structured logger backed by a [zap.Logger]. All methods are
// safe for concurrent use. Create one with [New], [NewProduction],
// [NewDevelopment] or [NewNop]; the zero value is not usable.
//
// Loggers derived with [Logger.With], [Logger.Named] and [Logger.Ctx] share
// the parent's output, redaction rules and level.
type Logger struct {
	z     *zap.Logger
	level zap.AtomicLevel
	// quietSync suppresses Sync errors for os.Stdout and os.Stderr, which
	// commonly fail to sync on terminals and pipes on every platform.
	quietSync bool
	// boundID is the request ID attached by Ctx, so the *Context methods
	// don't add it twice.
	boundID string
	// ctxBoundID is a mismatching ID already attached as ctx_request_id by
	// Ctx, so it isn't added a second time.
	ctxBoundID string
	// access is an unsampled twin of z used for access-log entries, so a
	// request flood cannot push them out through sampling. It is nil when
	// sampling is off (z is used instead).
	access *zap.Logger
}

// New builds a Logger from cfg.
func New(cfg Config) (*Logger, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	var ec zapcore.EncoderConfig
	if cfg.Development {
		ec = zap.NewDevelopmentEncoderConfig()
	} else {
		ec = zap.NewProductionEncoderConfig()
	}
	format := cfg.Format
	if format == "" {
		format = FormatJSON
		if cfg.Development {
			format = FormatConsole
		}
	}
	var enc zapcore.Encoder
	if format == FormatConsole {
		// The console encoder writes the message verbatim; escape control
		// characters so user input in a message can't forge log lines.
		enc = escapingEncoder{zapcore.NewConsoleEncoder(ec)}
	} else {
		enc = zapcore.NewJSONEncoder(ec)
	}

	out := cfg.Output
	if out == nil {
		out = os.Stderr
	}
	errOut := cfg.ErrorOutput
	if errOut == nil {
		errOut = os.Stderr
	}

	level := zap.NewAtomicLevelAt(cfg.Level)
	var core zapcore.Core = zapcore.NewCore(enc, lockedSyncer(out), level)
	if !cfg.Redaction.Disabled {
		core = &redactCore{Core: core, r: redactorFor(cfg.Redaction)}
	}
	unsampled := core
	if s := cfg.Sampling; s != nil {
		// The sampler sits outside redaction so sampled-out entries do
		// no redaction work.
		core = zapcore.NewSamplerWithOptions(core, s.Tick, s.Initial, s.Thereafter)
	}

	opts := []zap.Option{zap.AddCallerSkip(1), zap.ErrorOutput(lockedSyncer(errOut))}
	if !cfg.DisableCaller {
		opts = append(opts, zap.AddCaller())
	}
	if !cfg.DisableStacktrace {
		stackLevel := ErrorLevel
		if cfg.Development {
			stackLevel = WarnLevel
		}
		opts = append(opts, zap.AddStacktrace(stackLevel))
	}
	if cfg.Development {
		opts = append(opts, zap.Development())
	}
	var fields []zap.Field
	if cfg.Service != "" {
		fields = append(fields, zap.String("service", cfg.Service))
	}
	if cfg.Environment != "" {
		fields = append(fields, zap.String("env", cfg.Environment))
	}
	if cfg.Version != "" {
		fields = append(fields, zap.String("version", cfg.Version))
	}
	if len(fields) > 0 {
		opts = append(opts, zap.Fields(fields...))
	}

	l := &Logger{
		z:         zap.New(core, opts...),
		level:     level,
		quietSync: out == io.Writer(os.Stdout) || out == io.Writer(os.Stderr),
	}
	if cfg.Sampling != nil {
		l.access = zap.New(unsampled, opts...)
	}
	return l, nil
}

func lockedSyncer(w io.Writer) zapcore.WriteSyncer {
	return zapcore.Lock(zapcore.AddSync(w))
}

// NewProduction returns New(ProductionConfig(service)).
func NewProduction(service string) (*Logger, error) {
	return New(ProductionConfig(service))
}

// NewDevelopment returns New(DevelopmentConfig(service)).
func NewDevelopment(service string) (*Logger, error) {
	return New(DevelopmentConfig(service))
}

// NewNop returns a Logger that discards everything.
func NewNop() *Logger {
	return &Logger{z: zap.NewNop(), level: zap.NewAtomicLevelAt(zapcore.InvalidLevel)}
}

func (l *Logger) clone(z *zap.Logger) *Logger {
	c := *l
	c.z = z
	return &c
}

// With returns a child logger that adds fields to every entry. Sensitive
// fields are redacted once, here, rather than on every entry.
func (l *Logger) With(fields ...Field) *Logger {
	if len(fields) == 0 {
		return l
	}
	c := l.clone(l.z.With(fields...))
	if l.access != nil {
		c.access = l.access.With(fields...)
	}
	return c
}

// Named returns a child logger with name appended to the logger name,
// separated by a period.
func (l *Logger) Named(name string) *Logger {
	c := l.clone(l.z.Named(name))
	if l.access != nil {
		c.access = l.access.Named(name)
	}
	return c
}

// accessLogger returns the logger the middleware writes access entries to:
// never sampled, no caller (it would always be the middleware) and no
// automatic stack trace.
func (l *Logger) accessLogger() *zap.Logger {
	base := l.access
	if base == nil {
		base = l.z
	}
	return base.WithOptions(zap.WithCaller(false), zap.AddStacktrace(zapcore.InvalidLevel))
}

// Ctx returns a child logger carrying the request ID stored in ctx (see
// [WithRequestID] and [Logger.Middleware]), or l itself if there is none
// or l already carries that ID. Each call that binds an ID allocates a
// child; call it once per request and reuse the result.
//
// If l was already bound to a different request ID (a request-scoped logger
// reused for another request), the child keeps the original "request_id"
// and adds the new one as "ctx_request_id", so the mix-up is visible
// instead of silently attributing entries to the wrong request.
func (l *Logger) Ctx(ctx context.Context) *Logger {
	id, ok := RequestIDFromContext(ctx)
	if !ok || id == l.boundID || id == l.ctxBoundID {
		return l
	}
	if l.boundID != "" {
		c := l.clone(l.z.With(zap.String(ctxRequestIDKey, id)))
		c.ctxBoundID = id
		return c
	}
	c := l.clone(l.z.With(zap.String(RequestIDKey, id)))
	c.boundID = id
	return c
}

// ctxRequestIDKey reports a context request ID that differs from the one
// the logger is bound to.
const ctxRequestIDKey = "ctx_request_id"

// Zap returns the underlying *zap.Logger for interoperability with code
// that expects one. It writes through the same core, so redaction still
// applies to every field logged through it, including SugaredLogger use via
// Zap().Sugar(). Each call allocates; cache the result.
//
// Bypassing redaction is possible by replacing the core (for example
// zap.WrapCore); don't do that with untrusted data.
func (l *Logger) Zap() *zap.Logger {
	return l.z.WithOptions(zap.AddCallerSkip(-1))
}

// Level returns the current minimum level.
func (l *Logger) Level() Level { return l.level.Level() }

// SetLevel changes the minimum level at runtime. It affects l and every
// logger derived from or sharing a parent with it.
func (l *Logger) SetLevel(lvl Level) { l.level.SetLevel(lvl) }

// Enabled reports whether entries at lvl would be logged.
func (l *Logger) Enabled(lvl Level) bool { return l.z.Core().Enabled(lvl) }

// Sync flushes buffered output by calling Sync on the output writer, if it
// has one. Call it before the process exits (typically deferred in main).
// Errors from syncing os.Stdout or os.Stderr are ignored, because those are
// frequently terminals or pipes that cannot be synced.
func (l *Logger) Sync() error {
	err := l.z.Sync()
	if l.quietSync {
		return nil
	}
	return err
}

// Debug logs at DebugLevel.
func (l *Logger) Debug(msg string, fields ...Field) { l.z.Debug(msg, fields...) }

// Info logs at InfoLevel.
func (l *Logger) Info(msg string, fields ...Field) { l.z.Info(msg, fields...) }

// Warn logs at WarnLevel.
func (l *Logger) Warn(msg string, fields ...Field) { l.z.Warn(msg, fields...) }

// Error logs at ErrorLevel.
func (l *Logger) Error(msg string, fields ...Field) { l.z.Error(msg, fields...) }

// DPanic logs at DPanicLevel, then panics in development mode.
func (l *Logger) DPanic(msg string, fields ...Field) { l.z.DPanic(msg, fields...) }

// Panic logs at PanicLevel, then panics.
func (l *Logger) Panic(msg string, fields ...Field) { l.z.Panic(msg, fields...) }

// Fatal logs at FatalLevel, then calls os.Exit(1). Deferred functions
// (including a deferred Sync) do not run; Zap syncs the core itself first.
func (l *Logger) Fatal(msg string, fields ...Field) { l.z.Fatal(msg, fields...) }

// The *Context methods are like their counterparts but also add the
// request ID from ctx, if any. Each is written out (rather than sharing a
// helper) so the reported caller stays correct.

// DebugContext logs at DebugLevel with the request ID from ctx.
func (l *Logger) DebugContext(ctx context.Context, msg string, fields ...Field) {
	if ce := l.z.Check(DebugLevel, msg); ce != nil {
		ce.Write(l.ctxFields(ctx, fields)...)
	}
}

// InfoContext logs at InfoLevel with the request ID from ctx.
func (l *Logger) InfoContext(ctx context.Context, msg string, fields ...Field) {
	if ce := l.z.Check(InfoLevel, msg); ce != nil {
		ce.Write(l.ctxFields(ctx, fields)...)
	}
}

// WarnContext logs at WarnLevel with the request ID from ctx.
func (l *Logger) WarnContext(ctx context.Context, msg string, fields ...Field) {
	if ce := l.z.Check(WarnLevel, msg); ce != nil {
		ce.Write(l.ctxFields(ctx, fields)...)
	}
}

// ErrorContext logs at ErrorLevel with the request ID from ctx.
func (l *Logger) ErrorContext(ctx context.Context, msg string, fields ...Field) {
	if ce := l.z.Check(ErrorLevel, msg); ce != nil {
		ce.Write(l.ctxFields(ctx, fields)...)
	}
}

func (l *Logger) ctxFields(ctx context.Context, fields []Field) []Field {
	id, ok := RequestIDFromContext(ctx)
	if !ok || id == l.boundID || id == l.ctxBoundID {
		return fields
	}
	key := RequestIDKey
	if l.boundID != "" {
		key = ctxRequestIDKey // see Ctx
	}
	return append(fields[:len(fields):len(fields)], zap.String(key, id))
}

// escapingEncoder wraps the console encoder, which writes the message and
// logger name verbatim, and escapes control characters in them. Field values
// are already JSON-escaped by the console encoder.
type escapingEncoder struct{ zapcore.Encoder }

func (e escapingEncoder) Clone() zapcore.Encoder { return escapingEncoder{e.Encoder.Clone()} }

func (e escapingEncoder) EncodeEntry(ent zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	ent.Message = escapeControl(ent.Message)
	ent.LoggerName = escapeControl(ent.LoggerName)
	return e.Encoder.EncodeEntry(ent, fields)
}

// escapeControl escapes ASCII and C1 control characters (including CR, LF
// and ESC, which can forge lines or drive terminals), DEL, U+2028/U+2029
// and invalid UTF-8. It returns s unchanged, without allocating, when there
// is nothing to escape.
func escapeControl(s string) string {
	i := 0
	for i < len(s) {
		c := s[i]
		if c >= 0x20 && c < 0x7f {
			i++
			continue
		}
		if c < 0x80 { // ASCII control or DEL
			break
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if needsEscape(r, size) {
			break
		}
		i += size
	}
	if i == len(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	b.WriteString(s[:i])
	for i < len(s) {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case needsEscape(r, size):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

func needsEscape(r rune, size int) bool {
	return (r == utf8.RuneError && size == 1) || (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029
}
