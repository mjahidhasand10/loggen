package loggen

import (
	"bufio"
	"io"
	"net"
	"net/http"
)

// responseRecorder wraps an http.ResponseWriter to record the status code
// and body size.
//
// Optional interfaces are exposed truthfully: callers use type assertions
// such as w.(http.Flusher) or w.(http.Hijacker) to choose a code path, so
// the wrapper must not claim a capability the server's writer lacks. Each
// combination of Flusher, Hijacker and Pusher therefore has its own type
// (rwF, rwFH, ...), chosen once per request; the capability check follows
// Unwrap chains like http.ResponseController does. io.ReaderFrom is always
// exposed because io.Copy produces the same result with or without it.
type responseRecorder struct {
	w           http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
	hijacked    bool
}

func wrapResponseWriter(w http.ResponseWriter) (http.ResponseWriter, *responseRecorder) {
	f, h, p := supports[http.Flusher](w) || supports[interface{ FlushError() error }](w),
		supports[http.Hijacker](w), supports[http.Pusher](w)
	var ww http.ResponseWriter
	var rec *responseRecorder
	switch {
	case f && h && p:
		x := &rwFHP{responseRecorder{w: w}}
		ww, rec = x, &x.responseRecorder
	case f && h:
		x := &rwFH{responseRecorder{w: w}}
		ww, rec = x, &x.responseRecorder
	case f && p:
		x := &rwFP{responseRecorder{w: w}}
		ww, rec = x, &x.responseRecorder
	case h && p:
		x := &rwHP{responseRecorder{w: w}}
		ww, rec = x, &x.responseRecorder
	case f:
		x := &rwF{responseRecorder{w: w}}
		ww, rec = x, &x.responseRecorder
	case h:
		x := &rwH{responseRecorder{w: w}}
		ww, rec = x, &x.responseRecorder
	case p:
		x := &rwP{responseRecorder{w: w}}
		ww, rec = x, &x.responseRecorder
	default:
		rec = &responseRecorder{w: w}
		ww = rec
	}
	return ww, rec
}

// supports reports whether w, or a writer reachable through Unwrap, has
// the interface T.
func supports[T any](w http.ResponseWriter) bool {
	for i := 0; i < 16 && w != nil; i++ {
		if _, ok := w.(T); ok {
			return true
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return false
		}
		w = u.Unwrap()
	}
	return false
}

func (rw *responseRecorder) Header() http.Header { return rw.w.Header() }

func (rw *responseRecorder) WriteHeader(code int) {
	// 1xx responses other than 101 are informational (e.g. 103 Early
	// Hints) and may be followed by the real status.
	if !rw.wroteHeader && (code < 100 || code > 199 || code == http.StatusSwitchingProtocols) {
		rw.status = code
		rw.wroteHeader = true
	}
	rw.w.WriteHeader(code)
}

func (rw *responseRecorder) Write(b []byte) (int, error) {
	rw.implicitOK()
	n, err := rw.w.Write(b)
	rw.bytes += int64(n)
	return n, err
}

func (rw *responseRecorder) implicitOK() {
	if !rw.wroteHeader {
		rw.status = http.StatusOK
		rw.wroteHeader = true
	}
}

// ReadFrom lets io.Copy use the underlying writer's ReadFrom (sendfile on
// *http.response) while still counting bytes.
func (rw *responseRecorder) ReadFrom(src io.Reader) (int64, error) {
	rw.implicitOK()
	var n int64
	var err error
	if rf, ok := rw.w.(io.ReaderFrom); ok {
		n, err = rf.ReadFrom(src)
	} else {
		n, err = io.Copy(rw.w, src)
	}
	rw.bytes += n
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer for
// SetReadDeadline, SetWriteDeadline, EnableFullDuplex and future methods.
func (rw *responseRecorder) Unwrap() http.ResponseWriter { return rw.w }

func (rw *responseRecorder) flush() error {
	err := http.NewResponseController(rw.w).Flush()
	if err == nil {
		rw.implicitOK()
	}
	return err
}

func (rw *responseRecorder) hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := http.NewResponseController(rw.w).Hijack()
	if err == nil {
		rw.hijacked = true
	}
	return conn, brw, err
}

func (rw *responseRecorder) push(target string, opts *http.PushOptions) error {
	w := rw.w
	for i := 0; i < 16 && w != nil; i++ {
		if p, ok := w.(http.Pusher); ok {
			return p.Push(target, opts)
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			break
		}
		w = u.Unwrap()
	}
	return http.ErrNotSupported
}

// One type per combination of optional interfaces.
type (
	rwF   struct{ responseRecorder }
	rwH   struct{ responseRecorder }
	rwP   struct{ responseRecorder }
	rwFH  struct{ responseRecorder }
	rwFP  struct{ responseRecorder }
	rwHP  struct{ responseRecorder }
	rwFHP struct{ responseRecorder }
)

func (w *rwF) Flush()             { _ = w.flush() }
func (w *rwF) FlushError() error  { return w.flush() }
func (w *rwFH) Flush()            { _ = w.flush() }
func (w *rwFH) FlushError() error { return w.flush() }
func (w *rwFP) Flush()            { _ = w.flush() }
func (w *rwFP) FlushError() error { return w.flush() }
func (w *rwFHP) Flush()           { _ = w.flush() }
func (w *rwFHP) FlushError() error {
	return w.flush()
}

func (w *rwH) Hijack() (net.Conn, *bufio.ReadWriter, error)   { return w.hijack() }
func (w *rwFH) Hijack() (net.Conn, *bufio.ReadWriter, error)  { return w.hijack() }
func (w *rwHP) Hijack() (net.Conn, *bufio.ReadWriter, error)  { return w.hijack() }
func (w *rwFHP) Hijack() (net.Conn, *bufio.ReadWriter, error) { return w.hijack() }

func (w *rwP) Push(t string, o *http.PushOptions) error   { return w.push(t, o) }
func (w *rwFP) Push(t string, o *http.PushOptions) error  { return w.push(t, o) }
func (w *rwHP) Push(t string, o *http.PushOptions) error  { return w.push(t, o) }
func (w *rwFHP) Push(t string, o *http.PushOptions) error { return w.push(t, o) }

// Compile-time checks that each type has exactly its intended interfaces.
var (
	_ http.Flusher  = (*rwF)(nil)
	_ http.Hijacker = (*rwH)(nil)
	_ http.Pusher   = (*rwP)(nil)
	_ interface {
		http.Flusher
		http.Hijacker
		http.Pusher
		io.ReaderFrom
	} = (*rwFHP)(nil)
)
