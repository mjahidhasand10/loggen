package loggen

import (
	"fmt"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// DefaultRequestIDHeader is the header read and written by the middleware
// unless [MiddlewareConfig.RequestIDHeader] is set.
const DefaultRequestIDHeader = "X-Request-ID"

// DefaultMaxFieldBytes caps strings in access entries unless
// [MiddlewareConfig.MaxFieldBytes] is set.
const DefaultMaxFieldBytes = 2048

const truncatedSuffix = "...[truncated]"

// MiddlewareConfig configures [Logger.Middleware]. The zero value logs one
// entry per request, generates a fresh request ID for every request, and
// echoes it in the response header.
type MiddlewareConfig struct {
	// RequestIDHeader is read from requests and set on responses.
	// Empty means DefaultRequestIDHeader.
	RequestIDHeader string
	// TrustIncomingRequestID uses a valid client-supplied request ID (see
	// ValidRequestID) as the request ID, so it propagates from an upstream
	// gateway. Enable it only when the header is set by infrastructure you
	// control: otherwise clients choose their own correlation IDs and can
	// reuse another request's ID to confuse an investigation.
	//
	// By default a fresh ID is always generated; a valid incoming ID is
	// still logged, as "client_request_id", for cross-referencing.
	TrustIncomingRequestID bool
	// DisableRequestID turns request IDs off entirely.
	DisableRequestID bool
	// DisableResponseHeader stops the ID being echoed in the response.
	DisableResponseHeader bool

	// RecoverPanics recovers handler panics, logs them with a stack trace
	// and responds 500 if nothing was written yet. Without it the access
	// entry is still logged and the panic is re-raised for net/http.
	// http.ErrAbortHandler is never recovered.
	RecoverPanics bool

	// Skip, if set, bypasses the middleware (no log, no request ID) for
	// requests where it returns true, e.g. health checks.
	Skip func(*http.Request) bool
	// RouteFunc returns the route pattern to log. By default the pattern
	// set by http.ServeMux (Go 1.22+ patterns) is used, which only works
	// when the ServeMux receives this middleware's request directly (no
	// other middleware in between calling r.WithContext). Routers such as
	// chi expose their pattern differently; supply it here.
	RouteFunc func(*http.Request) string
	// ExtraFields adds fields to the access entry, for example a trace ID
	// from OpenTelemetry. It runs after the handler. String values are
	// capped at MaxFieldBytes.
	ExtraFields func(*http.Request) []Field
	// LevelFunc picks the level for a status code. The default logs 5xx at
	// Error, 4xx at Warn and everything else at Info.
	LevelFunc func(status int) Level
	// LogRemoteAddr logs r.RemoteAddr as "remote_addr". Forwarding headers
	// such as X-Forwarded-For are never trusted or logged.
	LogRemoteAddr bool
	// OmitPath leaves out the URL path. Use it when paths carry secrets
	// (for example /reset/{token}) and rely on the route pattern instead.
	OmitPath bool
	// MaxFieldBytes caps client-influenced strings in the access entry
	// (method, path, route, panic text, ExtraFields strings) so one request
	// can't write megabytes of log. Longer values are cut and end in
	// "...[truncated]". Zero means DefaultMaxFieldBytes; negative means no
	// limit.
	MaxFieldBytes int
	// Message is the access entry's message. Empty means "http request".
	Message string
}

// accessFields pools the access entry's field slice. Zap's core encodes
// fields synchronously inside Write and does not retain them (the redacting
// core copies before modifying), so the slice can be reused afterwards.
var accessFields = sync.Pool{New: func() any {
	s := make([]Field, 0, 16)
	return &s
}}

func defaultLevel(status int) Level {
	switch {
	case status >= 500:
		return ErrorLevel
	case status >= 400:
		return WarnLevel
	}
	return InfoLevel
}

// truncate cuts s to at most max bytes (plus the marker) on a UTF-8
// boundary. max <= 0 means no limit.
func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	n := max
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + truncatedSuffix
}

// safeCall runs a user callback, converting a panic into a returned value
// so it can't take down the access entry (or replace the handler's panic).
func safeCall[T any](fn func() T) (v T, p any) {
	defer func() { p = recover() }()
	v = fn()
	return
}

// Middleware returns net/http middleware that logs one access entry per
// request with method, route, path, status, response bytes, duration and
// request ID. It never logs request bodies, headers (including
// Authorization and Cookie) or the query string.
//
// Access entries are never sampled, even when the logger samples (as
// [ProductionConfig] does), so a request flood can't push them out of the
// log. Handler entries still follow the logger's sampling.
//
// The request's context carries the request ID ([RequestIDFromContext]) and
// l ([FromContext]), so handlers can log correlated entries with
// FromContext(ctx, l) or l.InfoContext(ctx, ...).
//
// The wrapped ResponseWriter exposes http.Flusher, http.Hijacker and
// http.Pusher only when the server's writer (or a writer it unwraps to)
// supports them, plus io.ReaderFrom and Unwrap for http.ResponseController,
// so streaming, server-sent events and WebSocket upgrades keep working and
// capability checks stay truthful.
func (l *Logger) Middleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	header := cfg.RequestIDHeader
	if header == "" {
		header = DefaultRequestIDHeader
	}
	header = http.CanonicalHeaderKey(header) // "X-Request-Id"
	msg := cfg.Message
	if msg == "" {
		msg = "http request"
	}
	maxBytes := cfg.MaxFieldBytes
	if maxBytes == 0 {
		maxBytes = DefaultMaxFieldBytes
	}
	access := l.accessLogger()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Skip != nil && cfg.Skip(r) {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			ctx := r.Context()

			var id, clientID string
			if !cfg.DisableRequestID {
				// header is already canonical, so index the map
				// directly instead of re-canonicalizing via Get.
				if v := r.Header[header]; len(v) > 0 && ValidRequestID(v[0]) {
					clientID = v[0]
				}
				if cfg.TrustIncomingRequestID && clientID != "" {
					id, clientID = clientID, ""
				} else {
					id = NewRequestID()
				}
				ctx = WithRequestID(ctx, id)
				// Set before the handler runs: once it writes, header
				// changes are ignored.
				if !cfg.DisableResponseHeader {
					w.Header()[header] = []string{id}
				}
			}
			ctx = NewContext(ctx, l)
			r2 := r.WithContext(ctx)
			ww, rec := wrapResponseWriter(w)

			defer func() {
				p := recover()
				aborted := p == http.ErrAbortHandler
				recovered := false
				if p != nil && !aborted && cfg.RecoverPanics {
					recovered = true
					if !rec.wroteHeader && !rec.hijacked {
						ww.WriteHeader(http.StatusInternalServerError)
					}
				}

				status := rec.status
				switch {
				case status != 0 || rec.hijacked:
				case p != nil && !recovered:
					// Nothing was sent: net/http drops the connection
					// (HTTP/1) or resets the stream (HTTP/2), so there
					// is no status to report.
				default:
					status = http.StatusOK
				}

				var cbPanics []any
				lvl := InfoLevel
				if p != nil && !aborted {
					lvl = ErrorLevel
				} else if cfg.LevelFunc != nil {
					var cp any
					if lvl, cp = safeCall(func() Level { return cfg.LevelFunc(status) }); cp != nil {
						lvl, cbPanics = ErrorLevel, append(cbPanics, cp)
					}
				} else {
					lvl = defaultLevel(status)
				}
				if aborted && status == 0 {
					lvl = max(lvl, WarnLevel)
				}

				if ce := access.Check(lvl, msg); ce != nil {
					fp := accessFields.Get().(*[]Field)
					fields := append((*fp)[:0], zap.String("method", truncate(r.Method, maxBytes)))
					route := r2.Pattern // set by ServeMux on r2
					if cfg.RouteFunc != nil {
						var cp any
						if route, cp = safeCall(func() string { return cfg.RouteFunc(r2) }); cp != nil {
							cbPanics = append(cbPanics, cp)
						}
					}
					if route != "" {
						fields = append(fields, zap.String("route", truncate(route, maxBytes)))
					}
					if !cfg.OmitPath {
						fields = append(fields, zap.String("path", truncate(r.URL.Path, maxBytes)))
					}
					if status != 0 {
						fields = append(fields, zap.Int("status", status))
					}
					fields = append(fields,
						zap.Int64("bytes", rec.bytes),
						zap.Duration("duration", time.Since(start)),
					)
					if id != "" {
						fields = append(fields, zap.String(RequestIDKey, id))
					}
					if clientID != "" {
						fields = append(fields, zap.String("client_request_id", clientID))
					}
					if cfg.LogRemoteAddr {
						fields = append(fields, zap.String("remote_addr", truncate(r.RemoteAddr, maxBytes)))
					}
					if rec.hijacked {
						fields = append(fields, zap.Bool("hijacked", true))
					}
					if aborted {
						fields = append(fields, zap.Bool("aborted", true))
					} else if p != nil {
						fields = append(fields,
							zap.String("panic", truncate(fmt.Sprint(p), maxBytes)),
							zap.Bool("recovered", recovered),
							zap.StackSkip("stack", 1),
						)
					}
					if cfg.ExtraFields != nil {
						extra, cp := safeCall(func() []Field { return cfg.ExtraFields(r2) })
						if cp != nil {
							cbPanics = append(cbPanics, cp)
						}
						for _, f := range extra {
							if f.Type == zapcore.StringType && len(f.String) > maxBytes && maxBytes > 0 {
								f = zap.String(f.Key, truncate(f.String, maxBytes))
							}
							fields = append(fields, f)
						}
					}
					if len(cbPanics) > 0 {
						// One field even if several callbacks panicked,
						// to avoid duplicate JSON keys.
						text := fmt.Sprint(cbPanics[0])
						for _, cp := range cbPanics[1:] {
							text += "; " + fmt.Sprint(cp)
						}
						fields = append(fields, zap.String("callback_panic", truncate(text, maxBytes)))
					}
					ce.Write(fields...)
					clear(fields) // drop references before pooling
					*fp = fields[:0]
					accessFields.Put(fp)
				}

				if p != nil && !recovered {
					panic(p)
				}
			}()

			next.ServeHTTP(ww, r2)
		})
	}
}
