package loggen

// Regression tests for the security review findings. Each test names the
// gap it guards against.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// --- Finding 1: cyclic or very deep values must not crash the process ---

type cyclic struct{ next *cyclic }

func (c *cyclic) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("name", "node")
	return enc.AddObject("next", c.next)
}

func TestRedactCyclicValuesDoNotCrash(t *testing.T) {
	m := map[string]any{"a": 1, "password": secret}
	m["self"] = m
	s := []any{"x"}
	s = append(s, nil)
	s[1] = s
	c := &cyclic{}
	c.next = c

	l, buf := newTestLogger(t, Config{})
	l.Info("m", zap.Any("map", m), zap.Any("slice", s), zap.Object("obj", c),
		zap.Any("named", namedMap{"me": nil}))
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("secret leaked: %.300s", out)
	}
	if !strings.Contains(out, depthPlaceholder) {
		t.Errorf("expected %q marker in output", depthPlaceholder)
	}
	if !json.Valid([]byte(strings.TrimSpace(out))) {
		t.Errorf("output is not valid JSON: %.300s", out)
	}
}

func TestRedactDepthLimit(t *testing.T) {
	// Nesting just inside the limit is fully redacted; beyond it, cut off.
	inner := map[string]any{"token": secret, "ok": "visible"}
	v := any(inner)
	for i := 0; i < MaxRedactDepth-1; i++ {
		v = map[string]any{"n": v}
	}
	l, buf := newTestLogger(t, Config{})
	l.Info("m", zap.Any("deep", v))
	out := buf.String()
	if strings.Contains(out, secret) || !strings.Contains(out, "visible") || strings.Contains(out, depthPlaceholder) {
		t.Errorf("at the limit: %s", out)
	}

	buf2 := &syncBuffer{}
	l2, _ := New(Config{Output: buf2})
	l2.Info("m", zap.Any("deeper", map[string]any{"n": v}))
	if strings.Contains(buf2.String(), secret) || !strings.Contains(buf2.String(), depthPlaceholder) {
		t.Errorf("past the limit: %s", buf2.String())
	}
}

// --- Finding 2: a request flood must not push access entries out ---

func TestAccessLogNotSampledUnderFlood(t *testing.T) {
	l, buf := newTestLogger(t, ProductionConfig("svc"))
	h := l.Middleware(MiddlewareConfig{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.InfoContext(r.Context(), "handler entry")
	}))
	for i := 0; i < 1000; i++ {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/flood", nil))
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/admin/delete-all", nil))

	access, handler := 0, 0
	for _, e := range buf.entries(t) {
		switch e["msg"] {
		case "http request":
			access++
		case "handler entry":
			handler++
		}
	}
	if access != 1001 || !strings.Contains(buf.String(), "/admin/delete-all") {
		t.Errorf("access entries = %d, want 1001 (attack logged: %v)", access, strings.Contains(buf.String(), "delete-all"))
	}
	if handler >= 1001 {
		t.Errorf("handler entries should still be sampled, got %d", handler)
	}
	// Child loggers keep the unsampled access path.
	buf2 := &syncBuffer{}
	cfg := ProductionConfig("svc")
	cfg.Output = buf2
	l2, _ := New(cfg)
	h2 := l2.With(String("component", "api")).Named("http").Middleware(MiddlewareConfig{})(http.NotFoundHandler())
	for i := 0; i < 300; i++ {
		h2.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))
	}
	if e := buf2.entries(t); len(e) != 300 || e[0]["component"] != "api" || e[0]["logger"] != "http" {
		t.Errorf("derived logger access entries = %d, first = %v", len(e), e[0])
	}
}

// --- Finding 3: named map types, pointers and generic maps ---

type namedMap map[string]any
type namedStrMap map[string]string
type keyType string

type jsonMap map[string]string

func (jsonMap) MarshalJSON() ([]byte, error) { return []byte(`{"custom":true}`), nil }

func TestRedactNamedAndGenericMaps(t *testing.T) {
	pm := map[string]any{"password": secret}
	l, buf := newTestLogger(t, Config{})
	l.Info("m",
		zap.Any("named", namedMap{"password": secret, "ok": 1}),
		zap.Any("namedStr", namedStrMap{"api_key": secret}),
		zap.Any("ptr", &pm),
		zap.Any("ints", map[string]int{"token_count": 5, "n": 1}),
		zap.Any("typedKeys", map[keyType]any{"secret": secret, "x": "y"}),
		zap.Any("structVals", map[string]credStruct{"password": {Password: secret}}),
		zap.Any("slice", []namedMap{{"jwt": secret}}),
		zap.Any("arr", [1]map[string]string{{"client_secret": secret}}),
		zap.Any("nested", map[string]any{"in": namedMap{"cookie": secret}}),
		zap.Any("custom", jsonMap{"x": "y"}),
	)
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("secret leaked: %s", out)
	}
	for _, want := range []string{
		`"named":{"ok":1,"password":"[REDACTED]"}`,
		`"namedStr":{"api_key":"[REDACTED]"}`,
		`"ptr":{"password":"[REDACTED]"}`,
		`"ints":{"n":1,"token_count":"[REDACTED]"}`,
		`"typedKeys":{"secret":"[REDACTED]","x":"y"}`,
		`"structVals":{"password":"[REDACTED]"}`,
		`"slice":[{"jwt":"[REDACTED]"}]`,
		`"arr":[{"client_secret":"[REDACTED]"}]`,
		`"nested":{"in":{"cookie":"[REDACTED]"}}`,
		`"custom":{"custom":true}`, // custom MarshalJSON is respected
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in\n%s", want, out)
		}
	}
}

// --- Finding 4: common secret key names ---

func TestRedactExtendedDefaults(t *testing.T) {
	r := newRedactor(RedactionConfig{})
	for _, k := range []string{
		"db_pass", "smtp_pass", "passphrase", "db_pwd", "auth", "basic_auth", "jwt", "id_jwt", "bearer",
		"dsn", "postgres_dsn", "database_url", "connection_string", "connstr", "encryption_key",
		"signing_key", "hmac_key", "master_key", "aws_access_key_id", "session", "sid", "otp", "totp",
		"pin", "salt", "signature", "x-hub-signature-256", "auth_header", "privkey",
	} {
		if !r.sensitive(k) {
			t.Errorf("%q not sensitive", k)
		}
	}
	for _, k := range []string{
		"passenger", "pass_rate_x", "path", "status", "user", "author", "cache_key", "key",
		"request_id", "spinner", "classname", "pinned", "otpauth_enabled_count_x",
	} {
		if r.sensitive(k) {
			t.Errorf("%q should not be sensitive", k)
		}
	}
	// Documented over-redaction from suffixes.
	for _, k := range []string{"oauth", "bypass", "compass"} {
		if !r.sensitive(k) {
			t.Errorf("%q: suffix rule changed; update the docs", k)
		}
	}
}

func TestRedactPIIAndSuffixConfig(t *testing.T) {
	r := newRedactor(RedactionConfig{RedactPII: true, Suffixes: []string{"_ref"}})
	for _, k := range []string{"ssn", "user_ssn", "card_number", "credit_card", "cvv", "iban", "date_of_birth", "order_ref"} {
		if !r.sensitive(k) {
			t.Errorf("%q not sensitive with RedactPII", k)
		}
	}
	if r.sensitive("classname") || r.sensitive("reference") {
		t.Error("PII/suffix rules over-match")
	}
	if newRedactor(RedactionConfig{}).sensitive("card_number") {
		t.Error("PII should be opt-in")
	}
	if !newRedactor(RedactionConfig{ReplaceDefaults: true, Suffixes: []string{"x"}}).sensitive("abcx") {
		t.Error("single-byte suffix not matched")
	}
	if err := (Config{Redaction: RedactionConfig{Suffixes: []string{"-"}}}).Validate(); err == nil {
		t.Error("empty suffix should be invalid")
	}
	if err := (Config{Redaction: RedactionConfig{ReplaceDefaults: true, RedactPII: true}}).Validate(); err != nil {
		t.Errorf("ReplaceDefaults+RedactPII is valid: %v", err)
	}
}

// --- Finding 5: URLs ---

func TestRedactURLs(t *testing.T) {
	u, _ := url.Parse("https://admin:" + secret + "@db.example.com/cb?api_key=" + secret + "&page=2#access_token=" + secret + "&state=s1")
	plain, _ := url.Parse("https://example.com/a?page=2")
	l, buf := newTestLogger(t, Config{})
	l.Info("m",
		zap.Any("any", u), zap.Stringer("stringer", u), URL("helper", u),
		zap.Any("value", *u), zap.Any("inmap", map[string]any{"u": u}),
		URL("plain", plain), zap.Any("bad", &url.URL{Scheme: "https", Host: "h", RawQuery: "token=%zz" + secret}),
		URL("nil", nil),
	)
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("secret leaked: %s", out)
	}
	want := `https://admin:REDACTED@db.example.com/cb?api_key=REDACTED&page=2#access_token=REDACTED&state=s1`
	e := buf.one(t)
	for _, k := range []string{"any", "stringer", "helper", "value"} {
		if e[k] != want {
			t.Errorf("%s = %v\nwant   %s", k, e[k], want)
		}
	}
	if e["inmap"].(map[string]any)["u"] != want || e["plain"] != "https://example.com/a?page=2" ||
		e["bad"] != "https://h?REDACTED" {
		t.Errorf("entry = %v", e)
	}
}

// --- Finding 7: console log forging ---

func TestConsoleEscapesControlCharacters(t *testing.T) {
	l, buf := newTestLogger(t, Config{Format: FormatConsole, DisableCaller: true})
	l.Named("svc\nINFO").Info("hi\n2026-01-01\tINFO\tadmin login ok\r\x1b[31m \xff", zap.String("v", "a\nb"))
	out := buf.String()
	if strings.Count(out, "\n") != 1 || strings.ContainsAny(out, "\r\x1b ") || strings.Contains(out, "\xff") {
		t.Fatalf("unescaped control characters: %q", out)
	}
	for _, want := range []string{`svc\nINFO`, `hi\n2026-01-01\tINFO\tadmin login ok\r\x1b[31m` + "\\" + `u2028` + `\xff`, `"v": "a\nb"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in %q", want, out)
		}
	}
	if s := "plain message ünïcode"; escapeControl(s) != s {
		t.Error("clean text was modified")
	}
	if a := testing.AllocsPerRun(100, func() { _ = escapeControl("clean message") }); a != 0 {
		t.Errorf("clean path allocs = %v", a)
	}
}

// --- Finding 8: log amplification ---

func TestAccessEntryLengthCaps(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	long := strings.Repeat("a", 500_000)
	cfg := MiddlewareConfig{
		RouteFunc:   func(*http.Request) string { return long },
		ExtraFields: func(*http.Request) []Field { return []Field{String("x", long), Int("n", 1)} },
	}
	serve(t, l, cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		httptest.NewRequest("GET", "/"+long, nil))
	if n := len(buf.String()); n > 4*DefaultMaxFieldBytes+1000 {
		t.Errorf("one request wrote %d bytes of log", n)
	}
	e := buf.one(t)
	for _, k := range []string{"path", "route", "x"} {
		if s, _ := e[k].(string); !strings.HasSuffix(s, truncatedSuffix) || len(s) > DefaultMaxFieldBytes+len(truncatedSuffix) {
			t.Errorf("%s not truncated (len %d)", k, len(s))
		}
	}

	l, buf = newTestLogger(t, Config{})
	serve(t, l, MiddlewareConfig{MaxFieldBytes: -1}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		httptest.NewRequest("GET", "/"+long, nil))
	if len(buf.one(t)["path"].(string)) != len(long)+1 {
		t.Error("MaxFieldBytes -1 should disable truncation")
	}
	if got := truncate("ééé", 3); got != "é"+truncatedSuffix {
		t.Errorf("truncate split a rune: %q", got)
	}
}

// --- Finding 9: optional interfaces are reported truthfully ---

type plainWriter struct{ h http.Header }

func (w *plainWriter) Header() http.Header         { return w.h }
func (w *plainWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *plainWriter) WriteHeader(int)             {}

// unwrapper is another middleware's wrapper that only exposes Unwrap.
type unwrapper struct{ http.ResponseWriter }

func (u unwrapper) Unwrap() http.ResponseWriter { return u.ResponseWriter }

func TestOptionalInterfacesTruthful(t *testing.T) {
	l, _ := newTestLogger(t, Config{})
	check := func(t *testing.T, w http.ResponseWriter, wantF, wantH, wantP bool) {
		t.Helper()
		h := l.Middleware(MiddlewareConfig{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, f := w.(http.Flusher)
			_, hj := w.(http.Hijacker)
			_, p := w.(http.Pusher)
			if f != wantF || hj != wantH || p != wantP {
				t.Errorf("Flusher=%v Hijacker=%v Pusher=%v, want %v %v %v", f, hj, p, wantF, wantH, wantP)
			}
			if _, ok := w.(io.ReaderFrom); !ok {
				t.Error("ReaderFrom should always be exposed")
			}
			if f {
				if err := http.NewResponseController(w).Flush(); err != nil {
					t.Errorf("Flush: %v", err)
				}
			}
		}))
		h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	}
	t.Run("plain", func(t *testing.T) { check(t, &plainWriter{h: http.Header{}}, false, false, false) })
	t.Run("recorder", func(t *testing.T) { check(t, httptest.NewRecorder(), true, false, false) })
	t.Run("through Unwrap", func(t *testing.T) { check(t, unwrapper{httptest.NewRecorder()}, true, false, false) })

	t.Run("HTTP/1 server", func(t *testing.T) {
		srv := httptest.NewServer(l.Middleware(MiddlewareConfig{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, f := w.(http.Flusher)
			_, hj := w.(http.Hijacker)
			_, p := w.(http.Pusher)
			fmt.Fprint(w, f, hj, p)
		})))
		defer srv.Close()
		resp, err := http.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "true true false" {
			t.Errorf("HTTP/1 capabilities = %s", body)
		}
	})
	t.Run("HTTP/2 server", func(t *testing.T) {
		srv := httptest.NewUnstartedServer(l.Middleware(MiddlewareConfig{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, f := w.(http.Flusher)
			_, hj := w.(http.Hijacker)
			_, p := w.(http.Pusher)
			fmt.Fprint(w, f, hj, p)
		})))
		srv.EnableHTTP2 = true
		srv.StartTLS()
		defer srv.Close()
		resp, err := srv.Client().Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "true false true" {
			t.Errorf("HTTP/2 capabilities = %s", body)
		}
	})
}

// --- Finding 10: status for unrecovered panics ---

func TestUnrecoveredPanicHasNoStatus(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	boom := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("x") })
	func() {
		defer func() { _ = recover() }()
		serve(t, l, MiddlewareConfig{}, boom, httptest.NewRequest("GET", "/", nil))
	}()
	if e := buf.one(t); e["status"] != nil || e["level"] != "error" {
		t.Errorf("entry = %v", e)
	}

	l, buf = newTestLogger(t, Config{})
	abort := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic(http.ErrAbortHandler) })
	func() {
		defer func() { _ = recover() }()
		serve(t, l, MiddlewareConfig{}, abort, httptest.NewRequest("GET", "/", nil))
	}()
	if e := buf.one(t); e["status"] != nil || e["aborted"] != true || e["level"] != "warn" {
		t.Errorf("aborted entry = %v", e)
	}
}

// --- Finding 11: redactor tables are shared ---

func TestRedactorCached(t *testing.T) {
	a := redactorFor(RedactionConfig{Keys: []string{"x"}})
	b := redactorFor(RedactionConfig{Keys: []string{"x"}})
	c := redactorFor(RedactionConfig{Keys: []string{"y"}})
	d := redactorFor(RedactionConfig{Substrings: []string{"x"}})
	if a != b || a == c || a == d {
		t.Error("redactor cache keyed incorrectly")
	}
	if a := testing.AllocsPerRun(10, func() { _, _ = New(Config{Output: io.Discard}) }); a > 100 {
		t.Errorf("New allocates %v times; the 136 KB table should be cached", a)
	}
}

// --- Finding 12: silent loss and wrong-request attribution ---

func TestFromContextNilFallbackIsNotNop(t *testing.T) {
	l := FromContext(context.Background(), nil)
	if !l.Enabled(InfoLevel) {
		t.Error("fallback logger drops entries")
	}
}

func TestBoundLoggerWithDifferentRequest(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	ctx1 := WithRequestID(context.Background(), "req-1")
	ctx2 := WithRequestID(context.Background(), "req-2")
	bound := l.Ctx(ctx1)
	if bound.Ctx(ctx1) != bound {
		t.Error("rebinding the same ID should be a no-op")
	}
	bound.InfoContext(ctx2, "a")
	bound.Ctx(ctx2).Info("b")
	bound.InfoContext(ctx1, "c")
	e := buf.entries(t)
	for _, x := range e[:2] {
		if x["request_id"] != "req-1" || x["ctx_request_id"] != "req-2" {
			t.Errorf("mismatch not reported: %v", x)
		}
	}
	if _, ok := e[2]["ctx_request_id"]; ok || strings.Count(buf.String(), `"request_id":"req-1"`) != 3 {
		t.Errorf("same-request entry wrong: %v", e[2])
	}

	// A rebound child used with the same mismatching context must not
	// repeat ctx_request_id.
	buf2 := &syncBuffer{}
	l2, _ := New(Config{Output: buf2})
	rebound := l2.Ctx(ctx1).Ctx(ctx2)
	rebound.InfoContext(ctx2, "d")
	if rebound.Ctx(ctx2) != rebound {
		t.Error("rebinding the same mismatching ID should be a no-op")
	}
	if n := strings.Count(buf2.String(), "ctx_request_id"); n != 1 {
		t.Errorf("ctx_request_id appears %d times: %s", n, buf2.String())
	}
}

// --- Finding 13: panicking callbacks ---

func TestPanickingCallbacks(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	cfg := MiddlewareConfig{
		RouteFunc:   func(*http.Request) string { panic("route boom") },
		ExtraFields: func(*http.Request) []Field { panic("extra boom") },
		LevelFunc:   func(int) Level { panic("level boom") },
	}
	var got any
	func() {
		defer func() { got = recover() }()
		serve(t, l, cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("handler boom") }),
			httptest.NewRequest("GET", "/", nil))
	}()
	if got != "handler boom" {
		t.Errorf("handler panic replaced by %v", got)
	}
	e := buf.one(t)
	if e["panic"] != "handler boom" || e["callback_panic"] != "route boom; extra boom" {
		t.Errorf("entry = %v", e)
	}

	l, buf = newTestLogger(t, Config{})
	serve(t, l, cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), httptest.NewRequest("GET", "/", nil))
	if e := buf.one(t); e["level"] != "error" || e["callback_panic"] != "level boom; route boom; extra boom" || e["status"] != 200.0 {
		t.Errorf("entry = %v", e)
	}
}

// --- Fuzz tests ---

func FuzzValidRequestID(f *testing.F) {
	for _, s := range []string{"", "abc", "a b", "x\r\ny", strings.Repeat("a", 129), "550e8400-e29b-41d4-a716-446655440000"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !ValidRequestID(s) {
			return
		}
		if len(s) == 0 || len(s) > MaxRequestIDLength {
			t.Fatalf("accepted bad length %d", len(s))
		}
		for _, c := range []byte(s) {
			if c <= ' ' || c >= 0x7f || c == '"' || c == '\\' {
				t.Fatalf("accepted %q", s)
			}
		}
	})
}

const fuzzMarker = "zzFUZZSECRETzz"

func FuzzRedactNestedMaps(f *testing.F) {
	f.Add("user", "password", uint8(3), true)
	f.Add("a", "Access-Token", uint8(40), false)
	f.Fuzz(func(t *testing.T, outer, leaf string, depth uint8, useSlice bool) {
		var v any = map[string]any{leaf: fuzzMarker}
		for i := 0; i < int(depth); i++ {
			if useSlice && i%2 == 1 {
				v = []any{v}
			} else {
				v = namedMap{outer: v}
			}
		}
		buf := &syncBuffer{}
		l, err := New(Config{Output: buf})
		if err != nil {
			t.Fatal(err)
		}
		l.Info("m", zap.Any("root", v))
		out := buf.String()
		if !json.Valid([]byte(strings.TrimSpace(out))) {
			t.Fatalf("invalid JSON: %.200q", out)
		}
		r := redactorFor(RedactionConfig{})
		if r.sensitive(leaf) && strings.Contains(out, fuzzMarker) {
			t.Fatalf("value under sensitive key %q leaked", leaf)
		}
	})
}

func FuzzEscapeControl(f *testing.F) {
	f.Add("hello\nworld\x1b[0m \xff")
	f.Fuzz(func(t *testing.T, s string) {
		out := escapeControl(s)
		if strings.ContainsAny(out, "\n\r") {
			t.Fatalf("output contains a line break: %q", out)
		}
		for _, r := range out {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029 {
				t.Fatalf("unescaped %U in %q", r, out)
			}
		}
		if !utf8.ValidString(out) {
			t.Fatalf("invalid UTF-8 in output: %q", out)
		}
	})
}
