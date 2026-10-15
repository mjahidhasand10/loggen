package loggen

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
)

// RequestIDKey is the field name used for request IDs in log entries. It is
// distinct from distributed-tracing fields such as "trace_id": a request ID
// identifies one HTTP request to this service, a trace ID spans services.
const RequestIDKey = "request_id"

// MaxRequestIDLength is the longest request ID accepted from a client.
const MaxRequestIDLength = 128

type ctxKey int

const (
	requestIDCtxKey ctxKey = iota
	loggerCtxKey
)

// NewRequestID returns a random 128-bit request ID as 32 lowercase hex
// characters, generated with crypto/rand.
func NewRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand only fails if the OS entropy source is broken;
		// since Go 1.24 it never returns an error at all.
		panic("loggen: crypto/rand failed: " + err.Error())
	}
	var out [32]byte
	hex.Encode(out[:], b[:])
	return string(out[:])
}

var requestIDChars = func() (t [256]bool) {
	for c := '0'; c <= '9'; c++ {
		t[c] = true
	}
	for c := 'a'; c <= 'z'; c++ {
		t[c] = true
		t[c-'a'+'A'] = true
	}
	for _, c := range "-_.:+/=@" {
		t[c] = true
	}
	return t
}()

// ValidRequestID reports whether id is acceptable as a client-supplied
// request ID: 1 to [MaxRequestIDLength] bytes of ASCII letters, digits and
// "-_.:+/=@". That admits UUIDs, ULIDs, hex and base64 IDs while rejecting
// whitespace, control characters, quotes and non-ASCII text.
func ValidRequestID(id string) bool {
	if len(id) == 0 || len(id) > MaxRequestIDLength {
		return false
	}
	for i := 0; i < len(id); i++ {
		if !requestIDChars[id[i]] {
			return false
		}
	}
	return true
}

// WithRequestID returns a copy of ctx carrying id. It does not validate id;
// the middleware validates client-supplied values before calling it.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDCtxKey, id)
}

// RequestIDFromContext returns the request ID stored in ctx, if any.
func RequestIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(requestIDCtxKey).(string)
	return id, ok && id != ""
}

// NewContext returns a copy of ctx carrying l. [Logger.Middleware] does
// this for every request.
func NewContext(ctx context.Context, l *Logger) context.Context {
	return context.WithValue(ctx, loggerCtxKey, l)
}

// FromContext returns the logger stored in ctx by [NewContext] or the
// middleware, with the context's request ID attached. If ctx has no
// logger, it returns fallback.Ctx(ctx). If fallback is also nil, it uses a
// built-in logger with the zero [Config] (JSON to stderr, redaction on), so
// entries are never silently dropped when the middleware is missing.
func FromContext(ctx context.Context, fallback *Logger) *Logger {
	l, _ := ctx.Value(loggerCtxKey).(*Logger)
	if l == nil {
		l = fallback
	}
	if l == nil {
		l = defaultLogger()
	}
	return l.Ctx(ctx)
}

// defaultLogger is immutable once built; it is not a settable global.
var defaultLogger = sync.OnceValue(func() *Logger {
	l, err := New(Config{})
	if err != nil { // the zero Config is always valid
		panic(err)
	}
	return l
})
