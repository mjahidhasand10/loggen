package loggen_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/mjahidhasand10/loggen"
)

func Example() {
	log, err := loggen.New(loggen.Config{
		Service:       "checkout",
		Output:        os.Stdout,
		DisableCaller: true,
	})
	if err != nil {
		panic(err)
	}
	defer log.Sync()

	log.Info("order placed",
		loggen.String("order_id", "o-123"),
		loggen.String("card_token", "tok_abc"),
		loggen.Int("items", 3),
	)
	// Output is one JSON line with "card_token":"[REDACTED]".
}

func ExampleLogger_Middleware() {
	log, _ := loggen.New(loggen.Config{Output: os.Stdout})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /orders/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := loggen.RequestIDFromContext(r.Context())
		log.InfoContext(r.Context(), "fetching order") // includes request_id
		fmt.Fprintln(w, "request", id)
	})

	handler := log.Middleware(loggen.MiddlewareConfig{RecoverPanics: true})(mux)
	_ = http.ListenAndServe // in a real program: http.ListenAndServe(":8080", handler)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/orders/7", nil)
	req.Header.Set("X-Request-ID", "demo-1")
	handler.ServeHTTP(rr, req)
	fmt.Println(rr.Body.String() == "request demo-1\n", rr.Header().Get("X-Request-ID"))
}

func ExampleLogger_Zap() {
	log, _ := loggen.New(loggen.Config{Output: os.Stdout})
	z := log.Zap()                                        // *zap.Logger for zap-based libraries
	z.Sugar().Infow("legacy call", "password", "hunter2") // still redacted
}

func ExampleValidRequestID() {
	fmt.Println(loggen.ValidRequestID("550e8400-e29b-41d4-a716-446655440000"))
	fmt.Println(loggen.ValidRequestID("bad\r\nid"))
	// Output:
	// true
	// false
}
