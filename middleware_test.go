package loggen

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func serve(t *testing.T, l *Logger, cfg MiddlewareConfig, h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	l.Middleware(cfg)(h).ServeHTTP(rr, req)
	return rr
}

func TestMiddlewareAccessEntry(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /users/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "hello")
	})

	req := httptest.NewRequest("GET", "/users/42?token=querysecret&x=1", strings.NewReader("bodysecret"))
	req.Header.Set("Authorization", "Bearer authsecret")
	req.Header.Set("Cookie", "sid=cookiesecret")
	rr := serve(t, l, MiddlewareConfig{}, mux, req)

	if rr.Code != http.StatusCreated || rr.Body.String() != "hello" {
		t.Fatalf("handler behavior changed: %d %q", rr.Code, rr.Body.String())
	}
	e := buf.one(t)
	want := map[string]any{
		"msg": "http request", "level": "info", "method": "GET", "route": "GET /users/{id}",
		"path": "/users/42", "status": 201.0, "bytes": 5.0,
	}
	for k, v := range want {
		if e[k] != v {
			t.Errorf("%s = %v, want %v", k, e[k], v)
		}
	}
	if _, ok := e["duration"].(float64); !ok {
		t.Errorf("duration = %v", e["duration"])
	}
	id, _ := e["request_id"].(string)
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id) || rr.Header().Get("X-Request-ID") != id {
		t.Errorf("request_id %q, response header %q", id, rr.Header().Get("X-Request-ID"))
	}
	if _, ok := e["caller"]; ok {
		t.Error("access entry should not have a caller")
	}
	out := buf.String()
	for _, s := range []string{"querysecret", "token=", "bodysecret", "authsecret", "cookiesecret", "Authorization", "Cookie"} {
		if strings.Contains(out, s) {
			t.Errorf("access log contains %q: %s", s, out)
		}
	}
}

func TestMiddlewareDefaultsAndLevels(t *testing.T) {
	tests := []struct {
		name    string
		h       http.HandlerFunc
		status  float64
		level   string
		noStack bool
	}{
		{"implicit 200", func(w http.ResponseWriter, r *http.Request) {}, 200, "info", true},
		{"write implies 200", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("x")) }, 200, "info", true},
		{"404 warns", http.NotFound, 404, "warn", true},
		{"500 errors", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }, 500, "error", true},
		{"early hints then 200", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusEarlyHints)
			w.WriteHeader(http.StatusOK)
		}, 200, "info", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, buf := newTestLogger(t, Config{})
			serve(t, l, MiddlewareConfig{}, tt.h, httptest.NewRequest("GET", "/", nil))
			e := buf.one(t)
			if e["status"] != tt.status || e["level"] != tt.level {
				t.Errorf("status %v level %v", e["status"], e["level"])
			}
			if _, ok := e["stacktrace"]; ok && tt.noStack {
				t.Error("access entry should not carry a stacktrace")
			}
		})
	}
}

func TestMiddlewareRequestID(t *testing.T) {
	ok := func(w http.ResponseWriter, r *http.Request) {}
	trust := MiddlewareConfig{TrustIncomingRequestID: true}
	tests := []struct {
		name       string
		cfg        MiddlewareConfig
		incoming   string
		wantSame   bool   // logged ID == incoming
		wantNone   bool   // no ID at all
		wantClient string // expected client_request_id
		noHeader   bool
	}{
		{"default generates and records client ID", MiddlewareConfig{}, "client-abc-123", false, false, "client-abc-123", false},
		{"default, invalid client ID dropped", MiddlewareConfig{}, "bad id\twith tab", false, false, "", false},
		{"trusted valid incoming used", trust, "client-abc-123", true, false, "", false},
		{"trusted invalid replaced", trust, "bad id\twith tab", false, false, "", false},
		{"trusted too long replaced", trust, strings.Repeat("a", 129), false, false, "", false},
		{"custom header", MiddlewareConfig{RequestIDHeader: "x-correlation-id"}, "", false, false, "", false},
		{"no response header", MiddlewareConfig{DisableResponseHeader: true}, "", false, false, "", true},
		{"disabled", MiddlewareConfig{DisableRequestID: true}, "client-abc-123", false, true, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, buf := newTestLogger(t, Config{})
			header := tt.cfg.RequestIDHeader
			if header == "" {
				header = DefaultRequestIDHeader
			}
			req := httptest.NewRequest("GET", "/", nil)
			if tt.incoming != "" {
				req.Header.Set(header, tt.incoming)
			}
			rr := serve(t, l, tt.cfg, http.HandlerFunc(ok), req)
			e := buf.one(t)
			id, has := e["request_id"].(string)
			switch {
			case tt.wantNone:
				if has {
					t.Fatalf("unexpected request_id %q", id)
				}
			case tt.wantSame:
				if id != tt.incoming {
					t.Fatalf("request_id = %q, want %q", id, tt.incoming)
				}
			default:
				if id == tt.incoming || !ValidRequestID(id) || len(id) != 32 {
					t.Fatalf("request_id = %q, want a fresh one", id)
				}
			}
			if got, _ := e["client_request_id"].(string); got != tt.wantClient {
				t.Errorf("client_request_id = %q, want %q", got, tt.wantClient)
			}
			got := rr.Header().Get(header)
			if tt.noHeader && got != "" {
				t.Errorf("response header = %q, want none", got)
			}
			if !tt.noHeader && got != id {
				t.Errorf("response header = %q, want %q", got, id)
			}
		})
	}
}

func TestMiddlewareResponseHeaderSetBeforeHandlerWrites(t *testing.T) {
	l, _ := newTestLogger(t, Config{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) })
	rr := serve(t, l, MiddlewareConfig{}, h, httptest.NewRequest("GET", "/", nil))
	// Result() reflects the headers snapshotted at WriteHeader time.
	if rr.Result().Header.Get("X-Request-ID") == "" {
		t.Error("request ID header missing when handler writes immediately")
	}
}

func TestMiddlewareHandlerLogsAreCorrelated(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		FromContext(r.Context(), nil).Info("from context", String("password", "p"))
		l.InfoContext(r.Context(), "info context")
		l.Named("db").Ctx(r.Context()).Info("ctx")
	})
	serve(t, l, MiddlewareConfig{}, h, httptest.NewRequest("GET", "/", nil))
	e := buf.entries(t)
	if len(e) != 4 {
		t.Fatalf("got %d entries", len(e))
	}
	id := e[3]["request_id"]
	for i, x := range e[:3] {
		if x["request_id"] != id || id == nil {
			t.Errorf("entry %d request_id = %v, want %v", i, x["request_id"], id)
		}
	}
	if e[0]["password"] != DefaultPlaceholder || e[2]["logger"] != "db" {
		t.Errorf("handler entries: %v", e[:3])
	}
}

func TestMiddlewarePanics(t *testing.T) {
	boom := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("kaboom") })

	t.Run("recovered", func(t *testing.T) {
		l, buf := newTestLogger(t, Config{})
		rr := serve(t, l, MiddlewareConfig{RecoverPanics: true}, boom, httptest.NewRequest("GET", "/", nil))
		if rr.Code != 500 {
			t.Errorf("status = %d, want 500", rr.Code)
		}
		e := buf.one(t)
		if e["level"] != "error" || e["panic"] != "kaboom" || e["recovered"] != true || e["status"] != 500.0 {
			t.Errorf("entry = %v", e)
		}
		if s, _ := e["stack"].(string); !strings.Contains(s, "middleware_test.go") {
			t.Errorf("stack should include the panicking handler: %q", s)
		}
	})

	t.Run("recovered after write keeps status", func(t *testing.T) {
		l, buf := newTestLogger(t, Config{})
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("partial"))
			panic("late")
		})
		rr := serve(t, l, MiddlewareConfig{RecoverPanics: true}, h, httptest.NewRequest("GET", "/", nil))
		if rr.Code != 200 || buf.one(t)["status"] != 200.0 {
			t.Errorf("status = %d", rr.Code)
		}
	})

	t.Run("not recovered re-panics", func(t *testing.T) {
		l, buf := newTestLogger(t, Config{})
		var got any
		func() {
			defer func() { got = recover() }()
			serve(t, l, MiddlewareConfig{}, boom, httptest.NewRequest("GET", "/", nil))
		}()
		if got != "kaboom" {
			t.Errorf("recovered %v, want the original panic", got)
		}
		e := buf.one(t)
		if e["panic"] != "kaboom" || e["recovered"] != false {
			t.Errorf("entry = %v", e)
		}
	})

	t.Run("ErrAbortHandler passes through", func(t *testing.T) {
		l, buf := newTestLogger(t, Config{})
		abort := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic(http.ErrAbortHandler) })
		var got any
		func() {
			defer func() { got = recover() }()
			serve(t, l, MiddlewareConfig{RecoverPanics: true}, abort, httptest.NewRequest("GET", "/", nil))
		}()
		if got != http.ErrAbortHandler {
			t.Errorf("recovered %v, want ErrAbortHandler", got)
		}
		if e := buf.one(t); e["aborted"] != true || e["panic"] != nil {
			t.Errorf("entry = %v", e)
		}
	})
}

func TestMiddlewareOptions(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	cfg := MiddlewareConfig{
		Skip:          func(r *http.Request) bool { return r.URL.Path == "/healthz" },
		RouteFunc:     func(r *http.Request) string { return "/custom/{x}" },
		ExtraFields:   func(r *http.Request) []Field { return []Field{String("trace_id", "t-1")} },
		LevelFunc:     func(int) Level { return DebugLevel },
		LogRemoteAddr: true,
		OmitPath:      true,
		Message:       "access",
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	rr := serve(t, l, cfg, ok, httptest.NewRequest("GET", "/healthz", nil))
	if rr.Header().Get("X-Request-ID") != "" || buf.String() != "" {
		t.Error("skipped request was processed")
	}

	serve(t, l, cfg, ok, httptest.NewRequest("GET", "/custom/1", nil))
	if buf.String() != "" {
		t.Error("LevelFunc=Debug should be filtered at Info")
	}
	l.SetLevel(DebugLevel)
	serve(t, l, cfg, ok, httptest.NewRequest("GET", "/custom/1", nil))
	e := buf.one(t)
	if e["msg"] != "access" || e["route"] != "/custom/{x}" || e["trace_id"] != "t-1" ||
		e["remote_addr"] != "192.0.2.1:1234" || e["path"] != nil || e["level"] != "debug" {
		t.Errorf("entry = %v", e)
	}
}

func TestMiddlewareOptionalInterfacesRecorder(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := w.(http.Hijacker); ok {
			t.Error("recorder is not a Hijacker; wrapper must not claim to be")
		}
		if _, ok := w.(http.Flusher); !ok {
			t.Error("Flusher lost")
		}
		if _, ok := w.(io.ReaderFrom); !ok {
			t.Error("ReaderFrom lost")
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("ResponseController.Flush: %v", err)
		}
		if _, _, err := http.NewResponseController(w).Hijack(); err == nil {
			t.Error("Hijack should be unsupported")
		}
		if _, ok := w.(http.Pusher); ok {
			t.Error("recorder is not a Pusher; wrapper must not claim to be")
		}
		n, err := io.Copy(w, strings.NewReader("0123456789"))
		if n != 10 || err != nil {
			t.Errorf("io.Copy = %d, %v", n, err)
		}
	})
	rr := serve(t, l, MiddlewareConfig{}, h, httptest.NewRequest("GET", "/", nil))
	if !rr.Flushed || rr.Body.String() != "0123456789" {
		t.Errorf("flushed=%v body=%q", rr.Flushed, rr.Body.String())
	}
	if e := buf.one(t); e["bytes"] != 10.0 || e["status"] != 200.0 {
		t.Errorf("entry = %v", e)
	}
}

func TestMiddlewareStreamingSSE(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	release := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		<-release
		fmt.Fprint(w, "data: two\n\n")
	})
	srv := httptest.NewServer(l.Middleware(MiddlewareConfig{})(h))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	line, err := br.ReadString('\n')
	if err != nil || line != "data: one\n" {
		t.Fatalf("first event not streamed before handler finished: %q %v", line, err)
	}
	close(release)
	rest, _ := io.ReadAll(br)
	if string(rest) != "\ndata: two\n\n" {
		t.Errorf("rest = %q", rest)
	}
	if e := buf.waitEntries(t, 1)[0]; e["bytes"] != 22.0 || e["status"] != 200.0 {
		t.Errorf("entry = %v", e)
	}
}

func TestMiddlewareReadFromRealServer(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	payload := strings.Repeat("x", 100_000)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := w.(interface{ Unwrap() http.ResponseWriter }).Unwrap().(io.ReaderFrom); !ok {
			t.Error("server writer should be a ReaderFrom; this test would not cover delegation")
		}
		// strings.Reader is a WriterTo, so hide that to force ReadFrom.
		n, err := io.Copy(w, struct{ io.Reader }{strings.NewReader(payload)})
		if n != int64(len(payload)) || err != nil {
			t.Errorf("io.Copy = %d, %v", n, err)
		}
	})
	srv := httptest.NewServer(l.Middleware(MiddlewareConfig{})(h))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if len(body) != len(payload) {
		t.Errorf("body length %d", len(body))
	}
	if e := buf.waitEntries(t, 1)[0]; e["bytes"] != float64(len(payload)) {
		t.Errorf("bytes = %v", e["bytes"])
	}
}

func TestMiddlewareHijackUpgrade(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Minute)); err != nil {
			t.Errorf("SetWriteDeadline through Unwrap: %v", err)
		}
		conn, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()
		msg, _ := brw.ReadString('\n')
		_, _ = brw.WriteString("echo:" + msg)
		_ = brw.Flush()
	})
	srv := httptest.NewServer(l.Middleware(MiddlewareConfig{})(h))
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade response: %v %v", resp, err)
	}
	fmt.Fprint(conn, "hi\n")
	if got, _ := br.ReadString('\n'); got != "echo:hi\n" {
		t.Errorf("echo = %q", got)
	}
	e := buf.waitEntries(t, 1)[0]
	if e["hijacked"] != true || e["status"] != nil || e["level"] != "info" {
		t.Errorf("entry = %v", e)
	}
}

func TestMiddlewareHTTP2NotHijackable(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("proto = %s, want HTTP/2", r.Proto)
		}
		if _, ok := w.(http.Hijacker); ok {
			t.Error("HTTP/2 writer must not appear hijackable")
		}
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "h2")
	})
	srv := httptest.NewUnstartedServer(l.Middleware(MiddlewareConfig{})(h))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	client := srv.Client()
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "h2" || resp.ProtoMajor != 2 {
		t.Errorf("body %q proto %s", body, resp.Proto)
	}
	if e := buf.waitEntries(t, 1)[0]; e["bytes"] != 2.0 {
		t.Errorf("entry = %v", e)
	}
}

func TestMiddlewareConcurrent(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	mux := http.NewServeMux()
	mux.HandleFunc("/item/{id}", func(w http.ResponseWriter, r *http.Request) {
		FromContext(r.Context(), l).Info("work", String("id", r.PathValue("id")))
		_, _ = io.WriteString(w, r.PathValue("id"))
	})
	srv := httptest.NewServer(l.Middleware(MiddlewareConfig{RecoverPanics: true})(mux))
	defer srv.Close()

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := http.Get(fmt.Sprintf("%s/item/%d", srv.URL, i))
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}(i)
	}
	wg.Wait()
	entries := buf.waitEntries(t, 2*n)
	ids := map[any]int{}
	for _, e := range entries {
		ids[e["request_id"]]++
	}
	if len(ids) != n {
		t.Errorf("distinct request IDs = %d, want %d", len(ids), n)
	}
	for id, c := range ids {
		if c != 2 {
			t.Errorf("request %v has %d entries, want 2", id, c)
		}
	}
}
