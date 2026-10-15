// Package loggen is a structured logging library for Go services built on
// Uber's Zap (go.uber.org/zap). Zap does the encoding and writing; loggen
// adds:
//
//   - Redaction of sensitive fields (passwords, tokens, API keys,
//     Authorization and Cookie headers, ...) before they reach the output,
//     implemented as a zapcore.Core wrapper.
//   - net/http access-log middleware that preserves optional
//     ResponseWriter interfaces (flushing, hijacking, ReadFrom).
//   - Request-ID generation, validation and propagation through
//     context.Context.
//   - A small configuration API with production and development presets.
//
// # Logging
//
// Use typed fields; they avoid reflection and allocations:
//
//	log, err := loggen.New(loggen.ProductionConfig("checkout"))
//	if err != nil { ... }
//	defer log.Sync()
//	log.Info("order placed", loggen.String("order_id", id), loggen.Int("items", n))
//
// loggen.Field is an alias of zap.Field, so zap.String and friends work too.
// [Logger.Zap] returns the underlying *zap.Logger (still redacting) for
// libraries that need one.
//
// # Redaction
//
// A field is redacted when its key, normalized by lowercasing and removing
// '-', '_', '.' and spaces, equals a sensitive key, contains a sensitive
// substring or ends with a sensitive suffix (see [DefaultSensitiveKeys],
// [DefaultSensitiveSubstrings], [DefaultSensitiveSuffixes]). The value is
// replaced by a string placeholder regardless of its type. Redaction applies
// to:
//
//   - fields passed to log methods and to With (redacted once, at With time);
//   - keys inside zap.Object, zap.Dict, zap.Inline, zap.Array and zap.Objects
//     values, recursively, for any zapcore.ObjectMarshaler/ArrayMarshaler;
//   - any map with string keys passed to zap.Any (including named types such
//     as gin.H and pointers to maps), http.Header, url.Values, and slices of
//     maps or interfaces, recursively;
//   - *url.URL and url.URL values: password and sensitive query/fragment
//     parameters are replaced (see [URL]);
//   - everything inside a zap.Namespace whose key is sensitive.
//
// Nesting deeper than [MaxRedactDepth] is replaced with "[MAX DEPTH]", so
// cyclic values can't recurse forever.
//
// It does NOT inspect:
//
//   - the log message text;
//   - other string values (a token in a free-form string or error message
//     is not detected), or non-URL fmt.Stringer output;
//   - fields of arbitrary structs logged with zap.Any (only the field's own
//     key is checked; implement zapcore.ObjectMarshaler to get per-field
//     redaction), or map types with a custom MarshalJSON.
//
// Redaction is a safety net. The reliable defense is not to log credentials.
//
// # Request IDs
//
// [Logger.Middleware] attaches a fresh request ID, from crypto/rand, to each
// request's context. A valid client-supplied X-Request-ID is logged as
// "client_request_id", or adopted as the request ID with
// [MiddlewareConfig.TrustIncomingRequestID]. Use [Logger.InfoContext] and
// friends, [Logger.Ctx] or [FromContext] to include it in handler logs.
// Request IDs are not trace IDs; add those with
// [MiddlewareConfig.ExtraFields].
//
// # Shutdown
//
// Call [Logger.Sync] before exiting to flush any buffered output.
package loggen
