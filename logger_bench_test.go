package loggen_test

import (
	"context"
	"io"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/mjahidhasand10/loggen"
)

// Both sides use Zap's production JSON encoder config, a mutex-locked
// io.Discard writer (loggen always locks its writer), Info level,
// stack traces at Error, no sampling, and the same typed fields.

func benchZap(caller bool) *zap.Logger {
	enc := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	core := zapcore.NewCore(enc, zapcore.Lock(zapcore.AddSync(io.Discard)), zap.NewAtomicLevelAt(zap.InfoLevel))
	opts := []zap.Option{zap.AddStacktrace(zap.ErrorLevel)}
	if caller {
		opts = append(opts, zap.AddCaller())
	}
	return zap.New(core, opts...)
}

func benchLoggen(b *testing.B, caller, redact bool) *loggen.Logger {
	l, err := loggen.New(loggen.Config{
		Output:        io.Discard,
		Level:         loggen.InfoLevel,
		DisableCaller: !caller,
		Redaction:     loggen.RedactionConfig{Disabled: !redact},
	})
	if err != nil {
		b.Fatal(err)
	}
	return l
}

func fiveFields() []zap.Field {
	return []zap.Field{
		zap.String("method", "GET"),
		zap.String("path", "/api/v1/users"),
		zap.Int("status", 200),
		zap.Duration("latency", 1500*time.Microsecond),
		zap.Bool("cache_hit", true),
	}
}

func tenFields() []zap.Field {
	return append(fiveFields(),
		zap.String("service", "users"),
		zap.String("region", "eu-west-1"),
		zap.Int("pid", 4242),
		zap.String("version", "1.2.3"),
		zap.Int64("build", 20261015),
	)
}

// benchLog runs a log call in a loop. Fields are built inside the loop, as
// real call sites do.
func benchLog(b *testing.B, z *zap.Logger, l *loggen.Logger) {
	b.ReportAllocs()
	b.ResetTimer()
	if z != nil {
		for i := 0; i < b.N; i++ {
			z.Info("request handled",
				zap.String("method", "GET"), zap.String("path", "/api/v1/users"), zap.Int("status", 200),
				zap.Duration("latency", 1500*time.Microsecond), zap.Bool("cache_hit", true))
		}
		return
	}
	for i := 0; i < b.N; i++ {
		l.Info("request handled",
			loggen.String("method", "GET"), loggen.String("path", "/api/v1/users"), loggen.Int("status", 200),
			loggen.Duration("latency", 1500*time.Microsecond), loggen.Bool("cache_hit", true))
	}
}

func BenchmarkInfo5Fields(b *testing.B) {
	for _, caller := range []bool{true, false} {
		name := "caller"
		if !caller {
			name = "nocaller"
		}
		b.Run(name+"/zap", func(b *testing.B) { benchLog(b, benchZap(caller), nil) })
		b.Run(name+"/loggen_noredact", func(b *testing.B) { benchLog(b, nil, benchLoggen(b, caller, false)) })
		b.Run(name+"/loggen_redact", func(b *testing.B) { benchLog(b, nil, benchLoggen(b, caller, true)) })
	}
}

// Two of the five keys are sensitive, so redaction copies the field slice.
func BenchmarkInfoSensitiveFields(b *testing.B) {
	b.Run("zap", func(b *testing.B) {
		z := benchZap(false)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			z.Info("login", zap.String("user", "bob"), zap.String("password", "hunter2"),
				zap.String("access_token", "abc"), zap.Int("attempt", 1), zap.Bool("ok", true))
		}
	})
	b.Run("loggen_redact", func(b *testing.B) {
		l := benchLoggen(b, false, true)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			l.Info("login", zap.String("user", "bob"), zap.String("password", "hunter2"),
				zap.String("access_token", "abc"), zap.Int("attempt", 1), zap.Bool("ok", true))
		}
	})
}

// A nested object forces the redacting encoder wrapper.
func BenchmarkInfoNestedObject(b *testing.B) {
	run := func(b *testing.B, log func(string, ...zap.Field)) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			log("user", zap.Dict("user", zap.String("name", "bob"), zap.Int("age", 42),
				zap.Dict("auth", zap.String("method", "oidc"), zap.String("refresh_token", "r"))))
		}
	}
	b.Run("zap", func(b *testing.B) { run(b, benchZap(false).Info) })
	b.Run("loggen_noredact", func(b *testing.B) { run(b, benchLoggen(b, false, false).Info) })
	b.Run("loggen_redact", func(b *testing.B) { run(b, benchLoggen(b, false, true).Info) })
}

func BenchmarkInfoMapAny(b *testing.B) {
	m := map[string]any{"user": "bob", "password": "x", "roles": []any{"a", "b"}, "n": 3}
	b.Run("zap", func(b *testing.B) {
		z := benchZap(false)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			z.Info("m", zap.Any("data", m))
		}
	})
	b.Run("loggen_redact", func(b *testing.B) {
		l := benchLoggen(b, false, true)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			l.Info("m", zap.Any("data", m))
		}
	})
}

// Ten persistent fields added once with With, then five per entry.
func BenchmarkWith10Persistent(b *testing.B) {
	b.Run("zap", func(b *testing.B) { benchLog(b, benchZap(false).With(tenFields()...), nil) })
	b.Run("loggen_noredact", func(b *testing.B) { benchLog(b, nil, benchLoggen(b, false, false).With(tenFields()...)) })
	b.Run("loggen_redact", func(b *testing.B) { benchLog(b, nil, benchLoggen(b, false, true).With(tenFields()...)) })
}

// Cost of creating a child logger (paid per request by Ctx/FromContext).
func BenchmarkWithCreate(b *testing.B) {
	b.Run("zap", func(b *testing.B) {
		z := benchZap(false)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = z.With(zap.String("request_id", "0123456789abcdef0123456789abcdef"))
		}
	})
	b.Run("loggen_redact", func(b *testing.B) {
		l := benchLoggen(b, false, true)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = l.With(loggen.String("request_id", "0123456789abcdef0123456789abcdef"))
		}
	})
}

func BenchmarkDisabledLevel(b *testing.B) {
	b.Run("zap", func(b *testing.B) {
		z := benchZap(true)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			z.Debug("dropped", zap.String("k", "v"), zap.Int("n", i))
		}
	})
	b.Run("loggen_redact", func(b *testing.B) {
		l := benchLoggen(b, true, true)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			l.Debug("dropped", loggen.String("k", "v"), loggen.Int("n", i))
		}
	})
}

func BenchmarkRequestIDField(b *testing.B) {
	const id = "0123456789abcdef0123456789abcdef"
	b.Run("zap_explicit_field", func(b *testing.B) {
		z := benchZap(false)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			z.Info("m", zap.String("k", "v"), zap.String("request_id", id))
		}
	})
	b.Run("loggen_InfoContext", func(b *testing.B) {
		l := benchLoggen(b, false, true)
		ctx := loggen.WithRequestID(context.Background(), id)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			l.InfoContext(ctx, "m", loggen.String("k", "v"))
		}
	})
}

func BenchmarkParallel(b *testing.B) {
	b.Run("zap", func(b *testing.B) {
		z := benchZap(true)
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				z.Info("request handled",
					zap.String("method", "GET"), zap.String("path", "/api/v1/users"), zap.Int("status", 200),
					zap.Duration("latency", 1500*time.Microsecond), zap.Bool("cache_hit", true))
			}
		})
	})
	b.Run("loggen_redact", func(b *testing.B) {
		l := benchLoggen(b, true, true)
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				l.Info("request handled",
					loggen.String("method", "GET"), loggen.String("path", "/api/v1/users"), loggen.Int("status", 200),
					loggen.Duration("latency", 1500*time.Microsecond), loggen.Bool("cache_hit", true))
			}
		})
	})
}
