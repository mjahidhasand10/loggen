# loggen

Structured logging for Go services, built on [Uber Zap](https://github.com/uber-go/zap).

Zap does the encoding and writing. loggen adds what services usually end up
building around it:

- **Redaction** of sensitive fields (passwords, tokens, API keys,
  `Authorization`/`Cookie` headers, …) before they reach the output,
  including nested objects, maps and fields attached with `With`.
- **HTTP access-log middleware** for `net/http` that keeps streaming, SSE,
  WebSocket upgrades and `http.ResponseController` working.
- **Request IDs**: generated with `crypto/rand`, validated when supplied by
  clients, propagated through `context.Context` into handler logs.
- A small **config API** with production and development presets, and
  direct access to the underlying `*zap.Logger`.

```
go get github.com/mjahidhasand10/loggen
```

Requires Go 1.23+. The only runtime dependency is `go.uber.org/zap` (which
brings `go.uber.org/multierr`).

## Quick start

```go
package main

import (
	"os"

	"github.com/mjahidhasand10/loggen"
)

func main() {
	log, err := loggen.NewProduction("checkout") // note: samples; see Configuration
	if err != nil {
		panic(err)
	}
	defer log.Sync()

	log.Info("order placed",
		loggen.String("order_id", "o-123"),
		loggen.Int("items", 3),
		loggen.String("card_token", "tok_abc"), // redacted
	)
}
```

```json
{"level":"info","ts":1792037725.53,"caller":"app/main.go:16","msg":"order placed","service":"checkout","env":"production","order_id":"o-123","items":3,"card_token":"[REDACTED]"}
```

## Configuration

```go
log, err := loggen.New(loggen.Config{
	Service:     "users-api",       // "service" field on every entry
	Environment: "staging",         // "env"
	Version:     "1.4.0",           // "version"
	Level:       loggen.InfoLevel,  // zero value is Info; change at runtime with SetLevel
	Format:      loggen.FormatJSON, // or FormatConsole
	Output:      os.Stdout,         // any io.Writer; default os.Stderr
	Redaction: loggen.RedactionConfig{
		Keys:       []string{"tenant_secret_id"}, // extra exact keys
		Substrings: []string{"card"},             // extra "contains" matches
		Suffixes:   []string{"_ref"},             // extra "ends with" matches
		RedactPII:  true,                         // card numbers, CVV, SSN, IBAN, date of birth
	},
})
```

| Preset | Encoder | Level | Stack traces | Sampling |
|---|---|---|---|---|
| `ProductionConfig(svc)` | Zap production JSON (epoch `ts`) | Info | Error+ | 100/s per level+message, then every 100th (access entries exempt) |
| `DevelopmentConfig(svc)` | Zap development console (ISO8601, colorless) | Debug | Warn+ | off |
| `Config{}` (zero value) | Zap production JSON | Info | Error+ | off |

> **Sampling.** Zap's sampler keys on level and message, so a flood of
> requests that log the same message (for example `"login failed"`) causes
> most repetitions to be dropped. That is acceptable for application noise
> but means an attacker can thin out handler logs. **Middleware access
> entries are never sampled**, so every request is still recorded. Set
> `cfg.Sampling = nil` if every application entry must be kept too.

Presets return a plain `Config`, so adjust fields before calling `New`.
`Config.Validate` (called by `New`) returns errors wrapping
`ErrInvalidFormat`, `ErrInvalidLevel`, `ErrInvalidSampling` or
`ErrInvalidRedaction`. `ParseLevel("warn")` parses level names from
environment variables or flags.

Writes to `Output` are serialized with a mutex, so any `io.Writer` is safe.
For file rotation, pass a rotating writer such as
`gopkg.in/natefinch/lumberjack.v2`; loggen doesn't depend on one.

## Logging with typed fields

```go
log.Info("payment captured",
	loggen.String("payment_id", id),
	loggen.Int64("amount_cents", 1999),
	loggen.Duration("latency", elapsed),
	loggen.Bool("retried", false),
	loggen.Err(err),
)

db := log.Named("db").With(loggen.String("pool", "primary"))
db.Warn("slow query", loggen.Duration("took", d))
```

`loggen.Field` is an alias of `zap.Field`, so `zap.String`, `zap.Object`,
`zap.Inline` etc. work wherever loggen takes a field. Prefer typed fields over
`loggen.Any`/`zap.Any` on hot paths: they avoid reflection.

Levels: `Debug`, `Info`, `Warn`, `Error`, `DPanic` (panics in development),
`Panic`, `Fatal` (calls `os.Exit(1)`). The `*Context` variants
(`InfoContext(ctx, …)`) add the request ID from `ctx`.

## HTTP middleware

```go
mux := http.NewServeMux()
mux.HandleFunc("GET /users/{id}", func(w http.ResponseWriter, r *http.Request) {
	log.InfoContext(r.Context(), "loading user") // carries request_id
	// or: reqLog := loggen.FromContext(r.Context(), log)
})

handler := log.Middleware(loggen.MiddlewareConfig{
	RecoverPanics: true,
	Skip: func(r *http.Request) bool { return r.URL.Path == "/healthz" },
})(mux)
http.ListenAndServe(":8080", handler)
```

One entry per request. Access entries are never sampled, even when the
logger samples, so a request flood can't push them out of the log.

```json
{"level":"info","ts":1792037739.25,"msg":"http request","service":"users-api","method":"GET","route":"GET /users/{id}","path":"/users/7","status":200,"bytes":11,"duration":0.0045,"request_id":"1f0c…","client_request_id":"my-id-123"}
```

| Field | Notes |
|---|---|
| `method`, `path` | `path` excludes the query string. `OmitPath` drops it when paths carry secrets. |
| `route` | The `http.ServeMux` pattern. It is only set when the mux receives the middleware's request directly; use `RouteFunc` for chi, gorilla, etc. |
| `status` | Final status; implicit 200 when the handler only writes; 1xx informational codes (103) are skipped. Absent for hijacked connections, and for panics that weren't recovered before anything was written (the client gets a dropped connection, not a status). |
| `bytes` | Response body bytes written (including via `io.Copy`/`ReadFrom`). |
| `duration` | Handler time, encoded per the encoder config (seconds in production JSON). On Windows the monotonic clock is coarse, so sub-millisecond requests may show 0. |
| `request_id`, `client_request_id` | See [Request ID correlation](#request-id-correlation). |
| `hijacked`, `panic`, `recovered`, `stack`, `aborted` | Only when they apply. |
| `callback_panic` | A `RouteFunc`, `ExtraFields` or `LevelFunc` callback panicked. The entry is still written, and a handler panic is still re-raised unchanged. |

Level is Error for 5xx and panics, Warn for 4xx and aborted requests, Info
otherwise (`LevelFunc` overrides). Access entries have no `caller` or
automatic stack trace, since both would always point at the middleware.

**Size limits:** `method`, `path`, `route`, `remote_addr`, panic text and
string `ExtraFields` are capped at `MaxFieldBytes` (default 2048) and end in
`...[truncated]` when cut. Without this, one request with a 500 KB URL wrote
500 KB of log. Set `MaxFieldBytes: -1` to disable the cap.

**Never logged by default:** request and response bodies, any header
(including `Authorization`, `Cookie`, `Set-Cookie`), the raw query string,
and client IP. `LogRemoteAddr` adds `r.RemoteAddr`; forwarding headers
(`X-Forwarded-For`, `Forwarded`) are never read.

**Panics:** with `RecoverPanics`, a panic is logged with its stack and a 500
is sent if nothing was written. Without it, the access entry is logged and
the panic is re-raised to `net/http`. `http.ErrAbortHandler` is always
re-raised.

**ResponseWriter behavior:** the wrapper exposes `http.Flusher`,
`http.Hijacker` and `http.Pusher` **only when the server's writer supports
them** (following `Unwrap` chains, as `http.ResponseController` does). Code
that checks `w.(http.Flusher)` or `w.(http.Hijacker)` therefore gets a
truthful answer: HTTP/1 is Flusher + Hijacker, HTTP/2 is Flusher + Pusher.
`io.ReaderFrom` (so `sendfile` still works) and `Unwrap()` for
`http.ResponseController` (deadlines, full duplex) are always present. Tests
cover SSE streaming, a raw `101 Switching Protocols` upgrade, HTTP/2, and
writers lacking each interface.

Other options: `ExtraFields` (for example to add an OpenTelemetry trace ID
without loggen depending on OTel), `Message`, `MaxFieldBytes`,
`DisableRequestID`, `DisableResponseHeader`, `RequestIDHeader`,
`TrustIncomingRequestID`.

## Request ID correlation

- **By default every request gets a fresh ID**: 128 bits from `crypto/rand`
  as 32 hex characters (`NewRequestID`). Clients can't choose it, so they
  can't reuse another request's ID to confuse an investigation.
- A client-supplied `X-Request-ID` (header name configurable) that passes
  `ValidRequestID` is still logged, as `client_request_id`, so you can
  cross-reference the client's own logs. Valid means 1–128 bytes of
  `A-Z a-z 0-9 - _ . : + / = @`, which covers UUIDs, ULIDs, hex and base64.
  Spaces, control characters, CR/LF, quotes, non-ASCII and over-long values
  are dropped.
- Behind a gateway you control that sets the header, use
  `TrustIncomingRequestID: true` to adopt a valid incoming ID as the
  `request_id` itself, so it propagates end to end.
- The ID is set on the response header **before** your handler runs, so it is
  present even if the handler writes immediately.
- It is stored in the request context: `RequestIDFromContext(ctx)`,
  `log.InfoContext(ctx, …)`, `log.Ctx(ctx)` (child logger with the ID; one
  allocation per call), `FromContext(ctx, fallback)` (the middleware's logger
  plus the ID). Without middleware and with a nil fallback, `FromContext`
  uses a built-in stderr JSON logger rather than silently discarding entries.
- If a logger already bound to one request ID (from `Ctx`) is used with a
  context carrying a different ID, the entry keeps `request_id` and adds
  `ctx_request_id`, so the mix-up is visible.
- Outside HTTP: `ctx = loggen.WithRequestID(ctx, id)`.
- Request IDs are **not** trace IDs. A request ID names one request to this
  service; a trace ID spans services. Log trace IDs under their own key via
  `ExtraFields`.

## Redaction

A field is redacted when its key, normalized by lowercasing and removing
`-`, `_`, `.` and spaces, **equals** a sensitive key, **contains** a
sensitive substring, or **ends with** a sensitive suffix. Its value,
whatever its type, becomes `"[REDACTED]"`.

- Default keys (`DefaultSensitiveKeys`): `pwd`, `pass`, `passwd`,
  `password`, `passwordhash`, `secret`, `clientsecret`, `token`,
  `accesstoken`, `refreshtoken`, `idtoken`, `bearertoken`, `sessiontoken`,
  `apikey`, `xapikey`, `authorization`, `proxyauthorization`, `auth`,
  `bearer`, `jwt`, `cookie`, `setcookie`, `privatekey`, `sessionid`,
  `session`, `sid`, `credentials`, `dsn`, `connstr`, `otp`, `pin`, `salt`.
- Default substrings (`DefaultSensitiveSubstrings`): `password`, `passwd`,
  `passphrase`, `secret`, `token`, `apikey`, `authorization`, `authheader`,
  `cookie`, `privatekey`, `privkey`, `credential`, `signature`,
  `connectionstring`, `databaseurl`, `encryptionkey`, `signingkey`,
  `hmackey`, `masterkey`, `accesskey`, `sessionkey`, `authkey`. So
  `db_password`, `csrf_token`, `X-Api-Key` and `aws_access_key_id` match.
- Default suffixes (`DefaultSensitiveSuffixes`): `pass`, `pwd`, `auth`,
  `jwt`, `dsn`, `otp`, `pin`, `sid`, `salt`. So `db_pass`, `smtp_pwd`,
  `basic_auth`, `postgres_dsn` and `totp` match, while `passenger` and
  `spinner` don't.
- Optional personal data (`RedactPII: true`): `ssn`, `dob`,
  `date_of_birth`, `iban`, card numbers, `cvv`/`cvc`.

This over-redacts on purpose: `token_count`, `oauth`, `bypass` and an
object field named `auth` are redacted too. Use `ReplaceDefaults` with your
own `Keys`/`Substrings`/`Suffixes` if that is a problem.

**Covered:**

- Fields passed to every log method, and to `With` (redacted once there, so
  persistent fields cost nothing per entry). Child loggers from `With`,
  `Named`, `Ctx`, the `*zap.Logger` from `Zap()`, and `Zap().Sugar()` all
  inherit it.
- Keys inside `zap.Object`, `zap.Dict`, `zap.Inline`, `zap.Objects`,
  `zap.Array`, and any `zapcore.ObjectMarshaler`/`ArrayMarshaler`,
  recursively, through every `ObjectEncoder` method.
- Any map with string keys passed to `zap.Any`, including named types such
  as `gin.H`, `echo.Map` and `logrus.Fields`, pointers to maps,
  `http.Header` and `url.Values`. Slices and arrays of maps or interfaces are
  covered too, all recursively. Keys are emitted sorted, as `encoding/json`
  does.
- **URLs** (`*url.URL` or `url.URL` via `zap.Any`/`zap.Stringer`, or the
  `loggen.URL` helper): the password and the values of sensitive query and
  fragment parameters become `REDACTED`, as in
  `https://admin:REDACTED@db/x?api_key=REDACTED&page=2`. An unparseable query
  is replaced entirely.
- Everything inside a `zap.Namespace` (or `OpenNamespace`) whose key is
  sensitive.
- **Cycles and deep nesting:** redaction walks at most `MaxRedactDepth` (32)
  levels and writes `"[MAX DEPTH]"` below that. A self-referencing map,
  which would otherwise recurse forever and crash the process with a stack
  overflow `recover()` can't catch, is logged safely.

**Not covered.** These are documented limitations. The `TestLimitation*`
tests in `redact_test.go` pin the first three:

- The log **message** text.
- Secrets inside other **values**: a free-form string, an error message, or
  a non-URL `fmt.Stringer`'s output.
- **Fields of arbitrary structs** passed to `zap.Any`. Only the field's own
  key is checked. Implement `zapcore.ObjectMarshaler` on the type to get
  per-field redaction (see `examples/basic`).
- Map types with a custom `MarshalJSON`. Their encoding is respected and
  not walked.
- Cores you add yourself around `Zap()`, for example via
  `zap.WrapCore`/`zapcore.NewTee`, that bypass loggen's core.

Redaction is a safety net. The reliable defense is to not log credentials in
the first place.

## Zap interoperability

```go
z := log.Zap()             // *zap.Logger; cache it, each call allocates
someLibrary.SetLogger(z)
z.Sugar().Infow("legacy", "password", "x") // still redacted
```

`Zap()` writes through the same core, so redaction, level and output are
shared, and the caller annotation is adjusted to point at your code.
`loggen.Level` is `zapcore.Level`, and `loggen.Field` is `zap.Field`.

## Shutdown and `Sync()`

```go
defer log.Sync()
```

`Sync` calls `Sync()` on the output writer if it has one (`*os.File` does),
flushing OS buffers. Call it before exit, after `http.Server.Shutdown`
returns, so in-flight access entries are written. Errors from syncing
`os.Stdout`/`os.Stderr` are ignored, because terminals and pipes routinely
reject sync on every platform. Errors from other writers (for example a
closed file) are returned. `Fatal` exits immediately without running
deferred calls, though Zap syncs its core first.

All `Logger` methods are safe for concurrent use. `SetLevel` changes the
level for the logger and every logger derived from the same `New` call.

## Benchmarks

Measured on 2026-10-15 (after the security fixes) with Go 1.26.3, windows/amd64, AMD Ryzen 3 3250U
(2 cores / 4 threads, laptop). `-count=5`. The table shows the **median** and
the **min** ns/op. This machine is noisy (some single runs were 3–5× slower),
so treat differences under ~15% as noise and rerun on your own hardware.

Zap and loggen are compared like-for-like. Both use Zap's production JSON
encoder config, a mutex-locked `io.Discard` writer, Info level, stack traces
at Error, no sampling, and the same typed fields built inside the loop.
Source: [`logger_bench_test.go`](logger_bench_test.go),
[`middleware_bench_test.go`](middleware_bench_test.go).

**Logging (5 typed fields unless noted)**

| Benchmark | Zap | loggen, redaction off | loggen, redaction on | B/op, allocs (Zap → loggen on) |
|---|---|---|---|---|
| Info, no caller | 1456 (1325) | 1343 (1302) | 1966 (1677) | 320 B, 1 → 320 B, 1 |
| Info, with caller | 3103 (2970) | 2732 (2503) | 3925 (3374) | 592 B, 3 → 592 B, 3 |
| Info, 2 of 5 keys sensitive | 2047 (1178)¹ | — | 1976 (1816) | 320 B, 1 → 640 B, 2 |
| Nested `zap.Dict` (2 levels) | 1938 (1411) | 1666 (1515) | 2092 (1770) | 432 B, 5 → 576 B, 8 |
| `zap.Any(map[string]any)` | 3727 (2861) | — | 3042 (2785) | 448 B, 11 → 360 B, 6 |
| 10 persistent `With` fields + 5 | 1541 (1215) | 1551 (1348) | 1951 (1827) | 320 B, 1 → 320 B, 1 |
| Create child with `With` (1 field) | 1395 (1217) | — | 1563 (1436) | 1360 B, 6 → 1440 B, 8 |
| Disabled level (Debug at Info) | 130 (110) | — | 136 (129) | 128 B, 1 → 128 B, 1 |
| `RunParallel`, with caller | 1848 (1743) | — | 2079 (1918) | 593 B, 3 → 593 B, 3 |
| Request ID: Zap explicit field vs `InfoContext` | 927 (829) | — | 1229 (1113) | 128 B, 1 → 192 B, 2 |

¹ Noise: the median is inflated by slow runs. Compare mins (1178 vs 1816 ns).

**HTTP middleware** (handler writes `"ok"`; minimal ResponseWriter; redaction on)

| Benchmark | ns/op median (min) | B/op | allocs/op |
|---|---|---|---|
| Bare handler, no middleware | 24 (22) | 2 | 1 |
| Middleware, request IDs disabled | 2257 (2069) | 418 | 4 |
| Middleware, generated request ID (default) | 3375 (3127) | 530 | 8 |
| Default + valid incoming ID logged as `client_request_id` | 3861 (3486) | 530 | 8 |
| `TrustIncomingRequestID` with valid incoming ID | 3083 (2697) | 498 | 7 |
| + ServeMux routing (`route` field) | 3893 (3668) | 546 | 9 |
| + handler logs once via `InfoContext` | 6547 (5789) | 1011 | 12 |
| + handler logs once via `FromContext` (builds a child logger) | 7735 (7211) | 2325 | 19 |

**What the numbers show:**

- **Wrapper cost is small.** loggen with redaction off matches Zap within
  noise (min 1302 vs 1325 ns without caller annotation). Disabled levels
  cost the same as Zap: about 130 ns and the one allocation for the
  variadic field slice, which comes from the call site, not loggen.
- **Redaction costs about 70–130 ns per field.** With 5 fields and no caller
  annotation, loggen adds about 350–500 ns over Zap (+25–35%) with no extra
  allocations. When a key matches, the field slice is copied: +1
  allocation, +320 B. Nested objects pay for an encoder wrapper per level.
- **Persistent fields** are redacted once, at `With` time, so ten of them
  cost nothing extra per entry. Creating the child costs about 10–20% more
  than Zap's `With`.
- **Reflected maps** come out *faster* than Zap's `zap.Any`. loggen encodes
  `map[string]any` itself with typed calls instead of `encoding/json`, and
  still redacts.
- **Caller annotation** (`runtime.Caller`) is the largest single cost for
  both libraries. Set `DisableCaller` if you don't need it.
- **Middleware** adds about 2.3 µs per request without request IDs, and about
  3.4 µs with a generated ID. Generating an ID with `crypto/rand` takes
  about 300–370 ns. Logging a client-supplied ID as `client_request_id` adds
  one more field. Prefer `InfoContext` over `FromContext` in hot handlers:
  `FromContext` builds a child logger on every call.

Internal microbenchmark: classifying a key takes about 30 ns for a
non-sensitive key like `status`, 40–50 ns for `access_token`, and about
150 ns for a long key that hits several pattern prefixes
(`user_password_hash`), all with zero allocations (`BenchmarkSensitiveKey`).

Reproduce:

```
go test -run='^$' -bench=. -benchmem -count=5 ./...
```

Use [benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat) to compare runs.

## Security considerations

- Redaction is key-based. See **Redaction → Not covered** above, and keep
  secrets out of messages and error strings. Log URLs as `*url.URL` (or with
  `loggen.URL`), not as pre-formatted strings, so they get redacted.
- Redaction can't crash the process: cycles and deep nesting are cut off at
  `MaxRedactDepth`. This is covered by tests and fuzzing.
- The middleware never logs headers, bodies or query strings. Path segments
  are logged; use `OmitPath` plus the route pattern for paths that carry
  tokens (`/reset/{token}`).
- Client-influenced strings in access entries are length-capped
  (`MaxFieldBytes`), so one request can't write megabytes of log.
- Access entries are never sampled, so a request flood can't erase the audit
  trail of other requests, including the attacker's own. Handler entries do
  follow the logger's sampling; see [Configuration](#configuration).
- Request IDs are generated server-side by default. Client-supplied IDs are
  validated, length-limited and logged separately as `client_request_id`
  unless you opt in with `TrustIncomingRequestID`.
- Forwarding headers are never trusted for client IP.
- In console format, control characters in the message and logger name
  (CR/LF, ESC, C1 controls, U+2028/2029, invalid UTF-8) are escaped, so user
  input in a message can't forge extra log lines or send terminal escape
  sequences. JSON output is escaped by Zap.
- Panic values are logged with `fmt.Sprint` (capped). Don't panic with
  secrets. A panicking `RouteFunc`/`ExtraFields`/`LevelFunc` callback is
  contained and reported as `callback_panic`.
- Log output goes only to the `io.Writer` you configure. loggen has no
  network, database or collector dependencies.

## Examples

- [`examples/basic`](examples/basic/main.go): presets, typed fields,
  redaction, child loggers, Zap interop. Run with `go run ./examples/basic`,
  or with `APP_ENV=development LOG_LEVEL=debug` set.
- [`examples/httpserver`](examples/httpserver/main.go): middleware with
  ServeMux routes, request IDs, SSE, panic recovery, graceful shutdown. Run
  with `go run ./examples/httpserver`.
- [`example_test.go`](example_test.go): godoc examples.

## Development

```
gofmt -l .
go vet ./...
go test ./...
go test -race ./...
go test -run='^$' -bench=. -benchmem ./...
```
