package loggen_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mjahidhasand10/loggen"
)

// discardRW is a minimal ResponseWriter so the benchmark measures the
// middleware, not httptest.ResponseRecorder.
type discardRW struct{ h http.Header }

func (w *discardRW) Header() http.Header         { return w.h }
func (w *discardRW) Write(p []byte) (int, error) { return len(p), nil }
func (w *discardRW) WriteHeader(int)             {}

func benchHandler(b *testing.B, h http.Handler, withIncomingID bool) {
	req := httptest.NewRequest("GET", "/api/v1/users/42", nil)
	if withIncomingID {
		req.Header.Set(loggen.DefaultRequestIDHeader, "client-0123456789")
	}
	w := &discardRW{h: make(http.Header)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.ServeHTTP(w, req)
	}
}

func BenchmarkMiddleware(b *testing.B) {
	l, err := loggen.New(loggen.Config{Output: io.Discard})
	if err != nil {
		b.Fatal(err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })

	b.Run("bare_handler", func(b *testing.B) { benchHandler(b, ok, false) })
	b.Run("no_request_id", func(b *testing.B) {
		benchHandler(b, l.Middleware(loggen.MiddlewareConfig{DisableRequestID: true})(ok), false)
	})
	b.Run("generated_request_id", func(b *testing.B) {
		benchHandler(b, l.Middleware(loggen.MiddlewareConfig{})(ok), false)
	})
	b.Run("incoming_id_logged_as_client_id", func(b *testing.B) {
		benchHandler(b, l.Middleware(loggen.MiddlewareConfig{})(ok), true)
	})
	b.Run("incoming_id_trusted", func(b *testing.B) {
		benchHandler(b, l.Middleware(loggen.MiddlewareConfig{TrustIncomingRequestID: true})(ok), true)
	})
	b.Run("handler_InfoContext", func(b *testing.B) {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			l.InfoContext(r.Context(), "work", loggen.Int("n", 1))
			_, _ = w.Write([]byte("ok"))
		})
		benchHandler(b, l.Middleware(loggen.MiddlewareConfig{})(h), false)
	})
	b.Run("handler_FromContext", func(b *testing.B) {
		// FromContext builds a child logger (one With) per request.
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			loggen.FromContext(r.Context(), l).Info("work", loggen.Int("n", 1))
			_, _ = w.Write([]byte("ok"))
		})
		benchHandler(b, l.Middleware(loggen.MiddlewareConfig{})(h), false)
	})
	b.Run("with_ServeMux_route", func(b *testing.B) {
		mux := http.NewServeMux()
		mux.Handle("GET /api/v1/users/{id}", ok)
		benchHandler(b, l.Middleware(loggen.MiddlewareConfig{})(mux), false)
	})
}
