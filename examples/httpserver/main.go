// Command httpserver shows the access-log middleware with ServeMux route
// patterns, request-ID correlation, a server-sent-events stream, panic
// recovery and graceful shutdown.
//
//	go run ./examples/httpserver
//	curl -i localhost:8080/users/42
//	curl -i -H 'X-Request-ID: my-id-123' localhost:8080/users/42
//	curl -N localhost:8080/events
//	curl -i localhost:8080/panic
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/mjahidhasand10/loggen"
)

func main() {
	log, err := loggen.New(loggen.Config{Service: "users-api", Environment: "local", Output: os.Stdout})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer log.Sync()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /users/{id}", func(w http.ResponseWriter, r *http.Request) {
		// Handler logs carry the same request_id as the access entry.
		log.InfoContext(r.Context(), "loading user", loggen.String("user_id", r.PathValue("id")))
		fmt.Fprintf(w, `{"id":%q}`+"\n", r.PathValue("id"))
	})
	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		reqLog := loggen.FromContext(r.Context(), log) // one child per request
		for i := 1; i <= 3; i++ {
			select {
			case <-r.Context().Done():
				reqLog.Info("client went away")
				return
			case <-time.After(500 * time.Millisecond):
			}
			fmt.Fprintf(w, "data: tick %d\n\n", i)
			w.(http.Flusher).Flush() // still works through the middleware
		}
	})
	mux.HandleFunc("GET /panic", func(w http.ResponseWriter, r *http.Request) {
		panic("something broke")
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	handler := log.Middleware(loggen.MiddlewareConfig{
		RecoverPanics: true,
		Skip:          func(r *http.Request) bool { return r.URL.Path == "/healthz" },
	})(mux)

	srv := &http.Server{Addr: ":8080", Handler: handler, ReadHeaderTimeout: 5 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Info("listening", loggen.String("addr", srv.Addr))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server failed", loggen.Err(err))
	}
	log.Info("stopped")
}
