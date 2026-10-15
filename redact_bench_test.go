package loggen

import "testing"

func BenchmarkSensitiveKey(b *testing.B) {
	r := newRedactor(RedactionConfig{})
	for _, k := range []string{"status", "cache_hit", "access_token", "user_password_hash"} {
		b.Run(k, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				r.sensitive(k)
			}
		})
	}
}

func BenchmarkNewRequestID(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = NewRequestID()
	}
}
