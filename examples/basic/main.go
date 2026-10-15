// Command basic shows configuration, typed fields, redaction, child
// loggers and Zap interoperability.
//
//	go run ./examples/basic            # production JSON
//	APP_ENV=development go run ./examples/basic
package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap/zapcore"

	"github.com/mjahidhasand10/loggen"
)

type user struct {
	ID       int
	Email    string
	Password string
}

// MarshalLogObject lets loggen redact nested fields by key.
func (u user) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddInt("id", u.ID)
	enc.AddString("email", u.Email)
	enc.AddString("password", u.Password) // redacted
	return nil
}

func main() {
	cfg := loggen.ProductionConfig("billing")
	if os.Getenv("APP_ENV") == "development" {
		cfg = loggen.DevelopmentConfig("billing")
	}
	cfg.Version = "1.4.0"
	cfg.Output = os.Stdout
	if lvl := os.Getenv("LOG_LEVEL"); lvl != "" {
		parsed, err := loggen.ParseLevel(lvl)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		cfg.Level = parsed
	}

	log, err := loggen.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer log.Sync() // flush before exit

	log.Info("service started",
		loggen.String("region", "eu-west-1"),
		loggen.Int("workers", 8),
		loggen.Duration("warmup", 250*time.Millisecond),
	)

	// Sensitive keys are redacted wherever they appear.
	log.Info("user signed up",
		loggen.Object("user", user{ID: 7, Email: "a@example.com", Password: "hunter2"}),
		loggen.String("access_token", "eyJhbGciOi..."),
		loggen.Any("headers", map[string]string{"Authorization": "Bearer abc", "Accept": "json"}),
	)

	// Child loggers carry fields; they are redacted once, at With time.
	payments := log.Named("payments").With(loggen.String("stripe_api_key", "sk_live_..."))
	payments.Warn("charge retried", loggen.Int("attempt", 2), loggen.Err(errors.New("card declined")))

	// Libraries that need a *zap.Logger get one that still redacts.
	z := log.Zap()
	z.Sugar().Infow("from a zap-based library", "client_secret", "abc", "ok", true)

	log.Debug("only visible with LOG_LEVEL=debug or APP_ENV=development")
}
