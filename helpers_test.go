package loggen

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a goroutine-safe buffer so tests can read output while
// server goroutines are still logging.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// entries decodes one JSON object per line.
func (b *syncBuffer) entries(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("invalid JSON line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// waitEntries polls until at least n entries exist (for logs written by
// server goroutines after the client has its response).
func (b *syncBuffer) waitEntries(t *testing.T, n int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if e := b.entries(t); len(e) >= n || time.Now().After(deadline) {
			if len(e) < n {
				t.Fatalf("got %d entries, want %d:\n%s", len(e), n, b.String())
			}
			return e
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (b *syncBuffer) one(t *testing.T) map[string]any {
	t.Helper()
	e := b.entries(t)
	if len(e) != 1 {
		t.Fatalf("got %d entries, want 1:\n%s", len(e), b.String())
	}
	return e[0]
}

func newTestLogger(t testing.TB, cfg Config) (*Logger, *syncBuffer) {
	t.Helper()
	buf := &syncBuffer{}
	cfg.Output = buf
	l, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return l, buf
}
