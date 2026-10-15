package loggen

import (
	"context"
	"regexp"
	"strings"
	"testing"
)

func TestNewRequestID(t *testing.T) {
	hex32 := regexp.MustCompile(`^[0-9a-f]{32}$`)
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := NewRequestID()
		if !hex32.MatchString(id) {
			t.Fatalf("NewRequestID() = %q", id)
		}
		if !ValidRequestID(id) {
			t.Fatalf("generated ID %q fails validation", id)
		}
		if seen[id] {
			t.Fatalf("duplicate ID %q", id)
		}
		seen[id] = true
	}
}

func TestValidRequestID(t *testing.T) {
	valid := []string{
		"a", "req-123", "550e8400-e29b-41d4-a716-446655440000", "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		"dGVzdA==", "svc:abc.def_1+2/3@x", strings.Repeat("a", MaxRequestIDLength),
	}
	invalid := []string{
		"", strings.Repeat("a", MaxRequestIDLength+1), "has space", "crlf\r\ninjected: 1",
		"nul\x00", "tab\t", "quote\"", "json{}", "<script>", "ünïcode", "semi;colon", "del\x7f",
	}
	for _, id := range valid {
		if !ValidRequestID(id) {
			t.Errorf("ValidRequestID(%q) = false", id)
		}
	}
	for _, id := range invalid {
		if ValidRequestID(id) {
			t.Errorf("ValidRequestID(%q) = true", id)
		}
	}
}

func TestRequestIDContext(t *testing.T) {
	ctx := context.Background()
	if _, ok := RequestIDFromContext(ctx); ok {
		t.Error("empty context has an ID")
	}
	if _, ok := RequestIDFromContext(WithRequestID(ctx, "")); ok {
		t.Error("empty ID should not count")
	}
	if id, ok := RequestIDFromContext(WithRequestID(ctx, "abc")); !ok || id != "abc" {
		t.Errorf("got %q, %v", id, ok)
	}
}

func TestFromContext(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	fallback, fbuf := newTestLogger(t, Config{})

	ctx := NewContext(WithRequestID(context.Background(), "r1"), l)
	FromContext(ctx, fallback).Info("stored")
	if e := buf.one(t); e["request_id"] != "r1" {
		t.Errorf("stored logger entry = %v", e)
	}

	FromContext(WithRequestID(context.Background(), "r2"), fallback).Info("fallback")
	if e := fbuf.one(t); e["request_id"] != "r2" {
		t.Errorf("fallback entry = %v", e)
	}

	FromContext(context.Background(), nil).Info("nop") // must not panic
}
