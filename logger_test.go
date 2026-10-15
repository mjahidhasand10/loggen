package loggen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestJSONOutput(t *testing.T) {
	l, buf := newTestLogger(t, Config{Service: "svc", Environment: "test", Version: "1.2.3"})
	l.Info("hello", String("user", "bob"), Int("n", 3), Bool("ok", true), Duration("d", time.Second))

	e := buf.one(t)
	want := map[string]any{
		"level": "info", "msg": "hello", "service": "svc", "env": "test", "version": "1.2.3",
		"user": "bob", "n": 3.0, "ok": true, "d": 1.0,
	}
	for k, v := range want {
		if e[k] != v {
			t.Errorf("%s = %v, want %v", k, e[k], v)
		}
	}
	if _, ok := e["ts"].(float64); !ok {
		t.Errorf("ts missing or not epoch seconds: %v", e["ts"])
	}
	if c, _ := e["caller"].(string); !strings.Contains(c, "logger_test.go") {
		t.Errorf("caller = %q, want logger_test.go", c)
	}
}

func TestCallerThroughZapInterop(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	l.Zap().Info("via zap")
	l.Zap().Sugar().Infow("via sugar")
	l.InfoContext(context.Background(), "via ctx")
	for _, e := range buf.entries(t) {
		if c, _ := e["caller"].(string); !strings.Contains(c, "logger_test.go") {
			t.Errorf("%s: caller = %q, want logger_test.go", e["msg"], c)
		}
	}
}

func TestLevelFiltering(t *testing.T) {
	l, buf := newTestLogger(t, Config{Level: WarnLevel})
	l.Debug("d")
	l.Info("i")
	l.Warn("w")
	l.Error("e")
	if got := len(buf.entries(t)); got != 2 {
		t.Fatalf("got %d entries, want 2", got)
	}
	if l.Enabled(InfoLevel) || !l.Enabled(WarnLevel) {
		t.Error("Enabled disagrees with level")
	}

	child := l.With(String("k", "v"))
	l.SetLevel(DebugLevel)
	if l.Level() != DebugLevel || !child.Enabled(DebugLevel) {
		t.Error("SetLevel should apply to derived loggers")
	}
	child.Debug("d2")
	if got := len(buf.entries(t)); got != 3 {
		t.Fatalf("got %d entries after SetLevel, want 3", got)
	}
}

func TestStacktraceOnError(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	l.Warn("w")
	l.Error("e")
	e := buf.entries(t)
	if _, ok := e[0]["stacktrace"]; ok {
		t.Error("warn should not have a stacktrace in production")
	}
	if _, ok := e[1]["stacktrace"]; !ok {
		t.Error("error should have a stacktrace")
	}

	l, buf = newTestLogger(t, Config{DisableStacktrace: true, DisableCaller: true})
	l.Error("e")
	e = buf.entries(t)
	if _, ok := e[0]["stacktrace"]; ok {
		t.Error("DisableStacktrace ignored")
	}
	if _, ok := e[0]["caller"]; ok {
		t.Error("DisableCaller ignored")
	}
}

func TestWithAndNamed(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	child := l.With(String("a", "1")).Named("db").With(Int("b", 2)).Named("pool")
	child.Info("x", String("c", "3"))
	l.Info("parent")

	e := buf.entries(t)
	if e[0]["a"] != "1" || e[0]["b"] != 2.0 || e[0]["c"] != "3" || e[0]["logger"] != "db.pool" {
		t.Errorf("child entry = %v", e[0])
	}
	if _, ok := e[1]["a"]; ok {
		t.Errorf("parent picked up child fields: %v", e[1])
	}
	if l.With() != l {
		t.Error("With() with no fields should return the receiver")
	}
}

func TestConsoleAndDevelopment(t *testing.T) {
	l, buf := newTestLogger(t, DevelopmentConfig("svc"))
	l.Debug("dev message", String("k", "v"), String("password", "hunter2"))
	out := buf.String()
	if !strings.Contains(out, "DEBUG") || !strings.Contains(out, "dev message") || !strings.Contains(out, `"k": "v"`) {
		t.Errorf("unexpected console output: %q", out)
	}
	if strings.Contains(out, "hunter2") {
		t.Errorf("console output leaked secret: %q", out)
	}
	defer func() {
		if recover() == nil {
			t.Error("DPanic should panic in development")
		}
	}()
	l.DPanic("boom")
}

func TestPanicLogsThenPanics(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	func() {
		defer func() { _ = recover() }()
		l.Panic("bad", String("token", "t"))
	}()
	e := buf.one(t)
	if e["level"] != "panic" || e["token"] != DefaultPlaceholder {
		t.Errorf("entry = %v", e)
	}
}

func TestContextMethods(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	ctx := WithRequestID(context.Background(), "req-1")

	l.InfoContext(ctx, "a")
	l.DebugContext(ctx, "filtered")
	l.WarnContext(ctx, "b")
	l.ErrorContext(context.Background(), "no id")
	l.Ctx(ctx).InfoContext(ctx, "bound")  // must not duplicate the key
	l.Ctx(context.Background()).Info("c") // no ID: same logger

	e := buf.entries(t)
	if len(e) != 5 {
		t.Fatalf("got %d entries", len(e))
	}
	for _, i := range []int{0, 1, 3} {
		if e[i]["request_id"] != "req-1" {
			t.Errorf("entry %d request_id = %v", i, e[i]["request_id"])
		}
	}
	if _, ok := e[2]["request_id"]; ok {
		t.Error("entry without ctx ID got one")
	}
	if n := strings.Count(buf.String(), `"request_id"`); n != 3 {
		t.Errorf("request_id appears %d times, want 3 (no duplicates)", n)
	}
}

type syncErrWriter struct{ err error }

func (w *syncErrWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *syncErrWriter) Sync() error                 { return w.err }

func TestSync(t *testing.T) {
	want := errors.New("disk gone")
	l, err := New(Config{Output: &syncErrWriter{err: want}})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Sync(); !errors.Is(err, want) {
		t.Errorf("Sync error = %v, want %v", err, want)
	}

	l, _ = New(Config{Output: io.Discard}) // no Sync method
	if err := l.Sync(); err != nil {
		t.Errorf("Sync on plain writer = %v", err)
	}

	for _, f := range []*os.File{os.Stdout, os.Stderr} {
		l, _ = New(Config{Output: f})
		if err := l.Sync(); err != nil {
			t.Errorf("Sync on %s should be quiet, got %v", f.Name(), err)
		}
	}
	if err := NewNop().Sync(); err != nil {
		t.Errorf("nop Sync = %v", err)
	}
}

func TestSyncClosedFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatal(err)
	}
	l, err := New(Config{Output: f, ErrorOutput: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	l.Info("before close")
	if err := l.Sync(); err != nil {
		t.Fatalf("Sync on open file: %v", err)
	}
	f.Close()
	if err := l.Sync(); err == nil {
		t.Error("Sync on closed file should fail")
	}
}

func TestSampling(t *testing.T) {
	l, buf := newTestLogger(t, Config{Sampling: &SamplingConfig{Tick: time.Hour, Initial: 2, Thereafter: 0}})
	for i := 0; i < 10; i++ {
		l.Info("same")
	}
	if got := len(buf.entries(t)); got != 2 {
		t.Errorf("sampled entries = %d, want 2", got)
	}
}

func TestNop(t *testing.T) {
	l := NewNop()
	l.Info("x")
	l.With(String("a", "b")).Ctx(context.Background()).ErrorContext(context.Background(), "y")
	if l.Enabled(FatalLevel) {
		t.Error("nop logger should be disabled")
	}
}

func TestConcurrentLogging(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	const goroutines, perG = 16, 200
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			child := l.With(Int("g", g), String("api_key", "k"))
			ctx := WithRequestID(context.Background(), fmt.Sprint("r", g))
			for i := 0; i < perG; i++ {
				child.InfoContext(ctx, "msg", Int("i", i), String("password", "p"))
				if i%50 == 0 {
					l.SetLevel(InfoLevel)
				}
			}
		}(g)
	}
	wg.Wait()
	e := buf.entries(t)
	if len(e) != goroutines*perG {
		t.Fatalf("got %d entries, want %d", len(e), goroutines*perG)
	}
	if strings.Contains(buf.String(), `"p"`) || strings.Contains(buf.String(), `"k"`) {
		t.Error("secret leaked under concurrency")
	}
}
