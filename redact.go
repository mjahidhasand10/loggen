package loggen

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// DefaultPlaceholder replaces redacted values unless
// [RedactionConfig.Placeholder] is set.
const DefaultPlaceholder = "[REDACTED]"

// MaxRedactDepth is the deepest nesting of objects, arrays and maps that
// redaction walks. Deeper values are replaced with "[MAX DEPTH]". This also
// stops self-referencing maps and cyclic marshalers from recursing forever.
const MaxRedactDepth = 32

const depthPlaceholder = "[MAX DEPTH]"

// urlPlaceholder replaces secrets inside URLs. It is URL-safe, unlike
// "[REDACTED]", which would be percent-encoded.
const urlPlaceholder = "REDACTED"

// DefaultSensitiveKeys are redacted when they match a key exactly (after
// normalization; see [RedactionConfig]).
var DefaultSensitiveKeys = []string{
	"pwd", "pass", "passwd", "password", "passwordhash",
	"secret", "clientsecret",
	"token", "accesstoken", "refreshtoken", "idtoken", "bearertoken", "sessiontoken",
	"apikey", "xapikey",
	"authorization", "proxyauthorization", "auth", "bearer", "jwt",
	"cookie", "setcookie",
	"privatekey", "sessionid", "session", "sid", "credentials",
	"dsn", "connstr", "otp", "pin", "salt",
}

// DefaultSensitiveSubstrings redact any key that contains them (after
// normalization), e.g. "db_password", "csrf_token" or "stripe_api_key".
// This deliberately over-redacts: a field named "token_count" is redacted.
var DefaultSensitiveSubstrings = []string{
	"password", "passwd", "passphrase", "secret", "token", "apikey",
	"authorization", "authheader", "cookie", "privatekey", "privkey", "credential",
	"signature", "connectionstring", "databaseurl",
	"encryptionkey", "signingkey", "hmackey", "masterkey", "accesskey", "sessionkey", "authkey",
}

// DefaultSensitiveSuffixes redact any key that ends with them (after
// normalization), e.g. "db_pass", "smtp_pwd", "basic_auth", "totp" or
// "postgres_dsn". Suffixes catch short names that would over-match as
// substrings ("pass" is in "passenger"). "oauth" and "bypass" are redacted
// too.
var DefaultSensitiveSuffixes = []string{
	"pass", "pwd", "auth", "jwt", "dsn", "otp", "pin", "sid", "salt",
}

// PII patterns are added when [RedactionConfig.RedactPII] is set.
var (
	PIIKeys       = []string{"ssn", "dob", "dateofbirth", "iban"}
	PIISubstrings = []string{"cardnumber", "creditcard", "cardnum", "cvv", "cvc", "socialsecurity"}
	PIISuffixes   = []string{"ssn"}
)

// normalizeKey lowercases ASCII letters and drops '-', '_', '.' and ' '.
func normalizeKey(k string) string {
	var b strings.Builder
	b.Grow(len(k))
	for i := 0; i < len(k); i++ {
		if c, ok := normByte(k[i]); ok {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func normByte(c byte) (byte, bool) {
	switch {
	case 'A' <= c && c <= 'Z':
		return c + ('a' - 'A'), true
	case c == '-' || c == '_' || c == '.' || c == ' ':
		return 0, false
	}
	return c, true
}

type matchKind uint8

const (
	matchExact matchKind = iota
	matchSubstring
	matchSuffix
)

// redactor decides which keys are sensitive and rewrites fields. It is
// immutable after construction and safe for concurrent use.
//
// Patterns of two or more bytes are indexed by their first two bytes.
// Matching scans each bigram of the key against a 64 Kbit bitset, so a
// typical non-sensitive key costs one bit test per byte and no map lookups
// or string comparisons. The tables take about 136 KB, so redactors are
// cached per configuration (see redactorFor).
type redactor struct {
	bigrams [1 << 16 / 64]uint64
	// slot maps a bigram to its index in groups (0 = none).
	slot   [1 << 16]uint16
	groups [][]pattern
	// Single-byte patterns, indexed by the byte.
	one [3][256]bool
	// placeholder replaces sensitive values.
	placeholder string
}

type pattern struct {
	s    string
	kind matchKind
}

var redactorCache sync.Map // cache key -> *redactor

// redactorFor returns a shared redactor for cfg, building it once.
func redactorFor(cfg RedactionConfig) *redactor {
	key := redactorCacheKey(cfg)
	if r, ok := redactorCache.Load(key); ok {
		return r.(*redactor)
	}
	r, _ := redactorCache.LoadOrStore(key, newRedactor(cfg))
	return r.(*redactor)
}

func redactorCacheKey(cfg RedactionConfig) string {
	var b strings.Builder
	write := func(s string) { // length-prefixed, so no separator ambiguity
		b.WriteString(strconv.Itoa(len(s)))
		b.WriteByte(':')
		b.WriteString(s)
	}
	write(cfg.Placeholder)
	write(strconv.FormatBool(cfg.ReplaceDefaults))
	write(strconv.FormatBool(cfg.RedactPII))
	for _, list := range [][]string{cfg.Keys, cfg.Substrings, cfg.Suffixes} {
		write(strconv.Itoa(len(list)))
		for _, s := range list {
			write(s)
		}
	}
	return b.String()
}

func newRedactor(cfg RedactionConfig) *redactor {
	r := &redactor{groups: make([][]pattern, 1), placeholder: cfg.Placeholder}
	if r.placeholder == "" {
		r.placeholder = DefaultPlaceholder
	}
	keys, subs, sufs := cfg.Keys, cfg.Substrings, cfg.Suffixes
	if !cfg.ReplaceDefaults {
		keys = append(slices.Clip(DefaultSensitiveKeys), keys...)
		subs = append(slices.Clip(DefaultSensitiveSubstrings), subs...)
		sufs = append(slices.Clip(DefaultSensitiveSuffixes), sufs...)
	}
	if cfg.RedactPII {
		keys = append(slices.Clip(keys), PIIKeys...)
		subs = append(slices.Clip(subs), PIISubstrings...)
		sufs = append(slices.Clip(sufs), PIISuffixes...)
	}
	add := func(s string, kind matchKind) {
		switch n := normalizeKey(s); len(n) {
		case 0:
		case 1:
			r.one[kind][n[0]] = true
		default:
			bg := uint16(n[0])<<8 | uint16(n[1])
			r.bigrams[bg>>6] |= 1 << (bg & 63)
			if r.slot[bg] == 0 {
				// At most 65535 distinct bigrams exist, so this fits.
				r.slot[bg] = uint16(len(r.groups))
				r.groups = append(r.groups, nil)
			}
			g := r.slot[bg]
			r.groups[g] = append(r.groups[g], pattern{n, kind})
		}
	}
	for _, k := range keys {
		add(k, matchExact)
	}
	for _, s := range subs {
		add(s, matchSubstring)
	}
	for _, s := range sufs {
		add(s, matchSuffix)
	}
	return r
}

// sensitive reports whether key names a value that must be redacted. Keys
// up to 64 bytes are normalized on the stack without allocating.
func (r *redactor) sensitive(key string) bool {
	if key == "" {
		return false
	}
	var buf [64]byte
	n := 0
	for i := 0; i < len(key); i++ {
		c, ok := normByte(key[i])
		if !ok {
			continue
		}
		if n == len(buf) {
			return r.matches([]byte(normalizeKey(key)))
		}
		buf[n] = c
		n++
	}
	return r.matches(buf[:n])
}

func (r *redactor) matches(norm []byte) bool {
	last := len(norm) - 1
	if last < 0 {
		return false
	}
	if (last == 0 && r.one[matchExact][norm[0]]) || r.one[matchSuffix][norm[last]] {
		return true
	}
	for i, c := range norm {
		if r.one[matchSubstring][c] {
			return true
		}
		if i == last {
			break
		}
		bg := uint16(c)<<8 | uint16(norm[i+1])
		if r.bigrams[bg>>6]&(1<<(bg&63)) == 0 {
			continue
		}
		for _, p := range r.groups[r.slot[bg]] {
			if !bytes.HasPrefix(norm[i:], []byte(p.s)) {
				continue
			}
			switch p.kind {
			case matchSubstring:
				return true
			case matchExact:
				if i == 0 && len(norm) == len(p.s) {
					return true
				}
			case matchSuffix:
				if i+len(p.s) == len(norm) {
					return true
				}
			}
		}
	}
	return false
}

// fields returns fs with sensitive values replaced. It never modifies fs:
// when nothing changes it returns fs itself (no allocation), otherwise a
// copy. inNS reports whether a sensitive namespace is already open; the
// returned bool reports whether one is open after these fields.
func (r *redactor) fields(fs []zapcore.Field, inNS bool) ([]zapcore.Field, bool) {
	var out []zapcore.Field
	for i := range fs {
		f, changed := r.field(fs[i], &inNS)
		if !changed {
			continue
		}
		if out == nil {
			out = make([]zapcore.Field, len(fs))
			copy(out, fs)
		}
		out[i] = f
	}
	if out == nil {
		return fs, inNS
	}
	return out, inNS
}

func (r *redactor) field(f zapcore.Field, inNS *bool) (zapcore.Field, bool) {
	switch f.Type {
	case zapcore.SkipType:
		return f, false
	case zapcore.NamespaceType:
		// Everything logged inside a sensitive namespace is redacted.
		if !*inNS && r.sensitive(f.Key) {
			*inNS = true
		}
		return f, false
	}
	if *inNS || r.sensitive(f.Key) {
		return zap.String(f.Key, r.placeholder), true
	}
	switch f.Type {
	case zapcore.ObjectMarshalerType:
		return zap.Object(f.Key, redactObject{r, f.Interface.(zapcore.ObjectMarshaler), 1}), true
	case zapcore.InlineMarshalerType:
		return zap.Inline(redactObject{r, f.Interface.(zapcore.ObjectMarshaler), 1}), true
	case zapcore.ArrayMarshalerType:
		return zap.Array(f.Key, redactArray{r, f.Interface.(zapcore.ArrayMarshaler), 1}), true
	case zapcore.StringerType:
		// zap.Any picks Stringer for *url.URL; other Stringers print as
		// they are (their output is not scanned).
		if u, ok := f.Interface.(*url.URL); ok && u != nil {
			return zap.String(f.Key, r.safeURL(u)), true
		}
	case zapcore.ReflectType:
		switch c := r.convert(f.Interface, 1); {
		case c.obj != nil:
			return zap.Object(f.Key, c.obj), true
		case c.arr != nil:
			return zap.Array(f.Key, c.arr), true
		case c.isStr:
			return zap.String(f.Key, c.str), true
		}
	}
	return f, false
}

// converted is a redaction-aware replacement for a reflected value: an
// object, an array, or a string. The zero value means "log unchanged".
type converted struct {
	obj   zapcore.ObjectMarshaler
	arr   zapcore.ArrayMarshaler
	str   string
	isStr bool
}

func (c converted) container() bool { return c.obj != nil || c.arr != nil }

var (
	mapAnyType      = reflect.TypeOf(map[string]any(nil))
	mapStringType   = reflect.TypeOf(map[string]string(nil))
	mapStringsType  = reflect.TypeOf(map[string][]string(nil))
	jsonMarshalType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
)

// convert turns values that zap would serialize with encoding/json (or as a
// Stringer, for URLs) into redacting equivalents. depth is the nesting level
// the result will be encoded at.
//
// Handled: any map with string keys (including named types such as gin.H
// and pointers to maps), slices and arrays of maps/interfaces/pointers/
// slices, and URLs. Structs and types with a custom MarshalJSON are left
// unchanged; see the package documentation.
func (r *redactor) convert(v any, depth int) converted {
	switch v := v.(type) {
	case nil:
		return converted{}
	case map[string]any:
		if v != nil {
			return converted{obj: mapAny{r, v, depth}}
		}
		return converted{}
	case map[string]string:
		if v != nil {
			return converted{obj: mapString{r, v, depth}}
		}
		return converted{}
	case http.Header:
		if v != nil {
			return converted{obj: mapStrings{r, v, depth}}
		}
		return converted{}
	case url.Values:
		if v != nil {
			return converted{obj: mapStrings{r, v, depth}}
		}
		return converted{}
	case []any:
		if v != nil {
			return converted{arr: sliceAny{r, v, depth}}
		}
		return converted{}
	case *url.URL:
		if v != nil {
			return converted{str: r.safeURL(v), isStr: true}
		}
		return converted{}
	case url.URL:
		return converted{str: r.safeURL(&v), isStr: true}
	case string, bool, int, int64, float64, error, time.Time, time.Duration:
		return converted{} // common scalars: skip reflection
	}
	return r.convertReflect(reflect.ValueOf(v), depth)
}

func (r *redactor) convertReflect(rv reflect.Value, depth int) converted {
	for i := 0; i < 8 && rv.Kind() == reflect.Pointer; i++ {
		if rv.IsNil() {
			return converted{}
		}
		rv = rv.Elem()
	}
	t := rv.Type()
	// Respect custom JSON encodings (they may already hide secrets, and
	// walking the map would change the output format).
	if t.Implements(jsonMarshalType) || reflect.PointerTo(t).Implements(jsonMarshalType) {
		return converted{}
	}
	switch rv.Kind() {
	case reflect.Map:
		if t.Key().Kind() != reflect.String || rv.IsNil() {
			return converted{}
		}
		switch {
		case t.ConvertibleTo(mapAnyType):
			return converted{obj: mapAny{r, rv.Convert(mapAnyType).Interface().(map[string]any), depth}}
		case t.ConvertibleTo(mapStringType):
			return converted{obj: mapString{r, rv.Convert(mapStringType).Interface().(map[string]string), depth}}
		case t.ConvertibleTo(mapStringsType):
			return converted{obj: mapStrings{r, rv.Convert(mapStringsType).Interface().(map[string][]string), depth}}
		}
		return converted{obj: reflectMap{r, rv, depth}}
	case reflect.Slice, reflect.Array:
		switch t.Elem().Kind() {
		case reflect.Map, reflect.Interface, reflect.Pointer, reflect.Slice, reflect.Array:
			if rv.Kind() == reflect.Slice && rv.IsNil() {
				return converted{}
			}
			return converted{arr: reflectSlice{r, rv, depth}}
		}
	}
	return converted{}
}

// safeURL returns u as a string with any password and the values of
// sensitive query (and fragment) parameters replaced.
func (r *redactor) safeURL(u *url.URL) string {
	c := *u
	if c.User != nil {
		if _, ok := c.User.Password(); ok {
			c.User = url.UserPassword(c.User.Username(), urlPlaceholder)
		}
	}
	c.RawQuery = r.safeQuery(c.RawQuery)
	if strings.Contains(c.Fragment, "=") { // e.g. OAuth implicit flow #access_token=...
		c.Fragment = r.safeQuery(c.EscapedFragment())
		if f, err := url.QueryUnescape(c.Fragment); err == nil {
			c.Fragment = f
		}
		c.RawFragment = ""
	}
	return c.String()
}

func (r *redactor) safeQuery(raw string) string {
	if raw == "" {
		return raw
	}
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return urlPlaceholder // unparseable: don't guess which part is safe
	}
	changed := false
	for k, vs := range vals {
		if r.sensitive(k) {
			for i := range vs {
				vs[i] = urlPlaceholder
			}
			changed = true
		}
	}
	if !changed {
		return raw
	}
	return vals.Encode()
}

// redactCore wraps a zapcore.Core and redacts fields before they reach it,
// both for per-entry fields (Write) and persistent ones (With). Fields added
// with With are redacted once, so they cost nothing on later entries.
type redactCore struct {
	zapcore.Core
	r *redactor
	// inNS is set once a sensitive namespace has been opened via With.
	inNS bool
}

var _ zapcore.Core = (*redactCore)(nil)

func (c *redactCore) Level() zapcore.Level { return zapcore.LevelOf(c.Core) }

func (c *redactCore) With(fields []zapcore.Field) zapcore.Core {
	fields, inNS := c.r.fields(fields, c.inNS)
	return &redactCore{Core: c.Core.With(fields), r: c.r, inNS: inNS}
}

// Check registers this core, not the inner one, so Write is always routed
// through redaction.
func (c *redactCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Core.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

func (c *redactCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	fields, _ = c.r.fields(fields, c.inNS)
	return c.Core.Write(ent, fields)
}

// redactObject and redactArray wrap user marshalers so that every nested
// key they emit is checked. depth is the nesting level of the wrapped value.
type redactObject struct {
	r     *redactor
	m     zapcore.ObjectMarshaler
	depth int
}

func (o redactObject) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return o.m.MarshalLogObject(&objectEncoder{r: o.r, enc: enc, depth: o.depth})
}

type redactArray struct {
	r     *redactor
	m     zapcore.ArrayMarshaler
	depth int
}

func (a redactArray) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	return a.m.MarshalLogArray(&arrayEncoder{ArrayEncoder: enc, r: a.r, depth: a.depth})
}

// objectEncoder is a zapcore.ObjectEncoder that redacts sensitive keys
// before forwarding to the real encoder.
type objectEncoder struct {
	r     *redactor
	enc   zapcore.ObjectEncoder
	depth int
	inNS  bool
}

func (e *objectEncoder) hide(key string) bool {
	if e.inNS || e.r.sensitive(key) {
		e.enc.AddString(key, e.r.placeholder)
		return true
	}
	return false
}

// tooDeep replaces a nested container that would exceed MaxRedactDepth.
func (e *objectEncoder) tooDeep(key string) bool {
	if e.depth >= MaxRedactDepth {
		e.enc.AddString(key, depthPlaceholder)
		return true
	}
	return false
}

func (e *objectEncoder) AddArray(key string, m zapcore.ArrayMarshaler) error {
	if e.hide(key) || e.tooDeep(key) {
		return nil
	}
	return e.enc.AddArray(key, redactArray{e.r, m, e.depth + 1})
}

func (e *objectEncoder) AddObject(key string, m zapcore.ObjectMarshaler) error {
	if e.hide(key) || e.tooDeep(key) {
		return nil
	}
	return e.enc.AddObject(key, redactObject{e.r, m, e.depth + 1})
}

func (e *objectEncoder) AddReflected(key string, v any) error {
	if e.hide(key) {
		return nil
	}
	c := e.r.convert(v, e.depth+1)
	if c.container() && e.tooDeep(key) {
		return nil
	}
	switch {
	case c.obj != nil:
		return e.enc.AddObject(key, c.obj)
	case c.arr != nil:
		return e.enc.AddArray(key, c.arr)
	case c.isStr:
		e.enc.AddString(key, c.str)
		return nil
	}
	return e.enc.AddReflected(key, v)
}

func (e *objectEncoder) OpenNamespace(key string) {
	if !e.inNS && e.r.sensitive(key) {
		e.inNS = true
	}
	e.enc.OpenNamespace(key)
}

func (e *objectEncoder) AddBinary(k string, v []byte) {
	if !e.hide(k) {
		e.enc.AddBinary(k, v)
	}
}

func (e *objectEncoder) AddByteString(k string, v []byte) {
	if !e.hide(k) {
		e.enc.AddByteString(k, v)
	}
}

func (e *objectEncoder) AddBool(k string, v bool) {
	if !e.hide(k) {
		e.enc.AddBool(k, v)
	}
}

func (e *objectEncoder) AddComplex128(k string, v complex128) {
	if !e.hide(k) {
		e.enc.AddComplex128(k, v)
	}
}

func (e *objectEncoder) AddComplex64(k string, v complex64) {
	if !e.hide(k) {
		e.enc.AddComplex64(k, v)
	}
}

func (e *objectEncoder) AddDuration(k string, v time.Duration) {
	if !e.hide(k) {
		e.enc.AddDuration(k, v)
	}
}

func (e *objectEncoder) AddFloat64(k string, v float64) {
	if !e.hide(k) {
		e.enc.AddFloat64(k, v)
	}
}

func (e *objectEncoder) AddFloat32(k string, v float32) {
	if !e.hide(k) {
		e.enc.AddFloat32(k, v)
	}
}

func (e *objectEncoder) AddInt(k string, v int) {
	if !e.hide(k) {
		e.enc.AddInt(k, v)
	}
}

func (e *objectEncoder) AddInt64(k string, v int64) {
	if !e.hide(k) {
		e.enc.AddInt64(k, v)
	}
}

func (e *objectEncoder) AddInt32(k string, v int32) {
	if !e.hide(k) {
		e.enc.AddInt32(k, v)
	}
}

func (e *objectEncoder) AddInt16(k string, v int16) {
	if !e.hide(k) {
		e.enc.AddInt16(k, v)
	}
}

func (e *objectEncoder) AddInt8(k string, v int8) {
	if !e.hide(k) {
		e.enc.AddInt8(k, v)
	}
}

func (e *objectEncoder) AddString(k, v string) {
	if !e.hide(k) {
		e.enc.AddString(k, v)
	}
}

func (e *objectEncoder) AddTime(k string, v time.Time) {
	if !e.hide(k) {
		e.enc.AddTime(k, v)
	}
}

func (e *objectEncoder) AddUint(k string, v uint) {
	if !e.hide(k) {
		e.enc.AddUint(k, v)
	}
}

func (e *objectEncoder) AddUint64(k string, v uint64) {
	if !e.hide(k) {
		e.enc.AddUint64(k, v)
	}
}

func (e *objectEncoder) AddUint32(k string, v uint32) {
	if !e.hide(k) {
		e.enc.AddUint32(k, v)
	}
}

func (e *objectEncoder) AddUint16(k string, v uint16) {
	if !e.hide(k) {
		e.enc.AddUint16(k, v)
	}
}

func (e *objectEncoder) AddUint8(k string, v uint8) {
	if !e.hide(k) {
		e.enc.AddUint8(k, v)
	}
}

func (e *objectEncoder) AddUintptr(k string, v uintptr) {
	if !e.hide(k) {
		e.enc.AddUintptr(k, v)
	}
}

// arrayEncoder forwards primitive elements unchanged (they have no keys)
// and wraps nested objects, arrays and reflected values.
type arrayEncoder struct {
	zapcore.ArrayEncoder
	r     *redactor
	depth int
}

func (e *arrayEncoder) tooDeep() bool {
	if e.depth >= MaxRedactDepth {
		e.ArrayEncoder.AppendString(depthPlaceholder)
		return true
	}
	return false
}

func (e *arrayEncoder) AppendObject(m zapcore.ObjectMarshaler) error {
	if e.tooDeep() {
		return nil
	}
	return e.ArrayEncoder.AppendObject(redactObject{e.r, m, e.depth + 1})
}

func (e *arrayEncoder) AppendArray(m zapcore.ArrayMarshaler) error {
	if e.tooDeep() {
		return nil
	}
	return e.ArrayEncoder.AppendArray(redactArray{e.r, m, e.depth + 1})
}

func (e *arrayEncoder) AppendReflected(v any) error {
	c := e.r.convert(v, e.depth+1)
	if c.container() && e.tooDeep() {
		return nil
	}
	switch {
	case c.obj != nil:
		return e.ArrayEncoder.AppendObject(c.obj)
	case c.arr != nil:
		return e.ArrayEncoder.AppendArray(c.arr)
	case c.isStr:
		e.ArrayEncoder.AppendString(c.str)
		return nil
	}
	return e.ArrayEncoder.AppendReflected(v)
}

// Marshalers for the reflected types handled by redactor.convert. Map keys
// are emitted in sorted order, matching encoding/json (which zap.Any uses).

type mapAny struct {
	r     *redactor
	m     map[string]any
	depth int
}

func (m mapAny) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	e := &objectEncoder{r: m.r, enc: enc, depth: m.depth}
	for _, k := range sortedKeys(m.m) {
		if err := addAny(e, k, m.m[k]); err != nil {
			return err
		}
	}
	return nil
}

// addAny encodes common JSON scalar types directly and everything else via
// AddReflected (which recurses into supported containers).
func addAny(e *objectEncoder, k string, v any) error {
	switch v := v.(type) {
	case string:
		e.AddString(k, v)
	case bool:
		e.AddBool(k, v)
	case int:
		e.AddInt(k, v)
	case int64:
		e.AddInt64(k, v)
	case float64:
		e.AddFloat64(k, v)
	default:
		return e.AddReflected(k, v)
	}
	return nil
}

type mapString struct {
	r     *redactor
	m     map[string]string
	depth int
}

func (m mapString) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	e := &objectEncoder{r: m.r, enc: enc, depth: m.depth}
	for _, k := range sortedKeys(m.m) {
		e.AddString(k, m.m[k])
	}
	return nil
}

type mapStrings struct {
	r     *redactor
	m     map[string][]string
	depth int
}

func (m mapStrings) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	e := &objectEncoder{r: m.r, enc: enc, depth: m.depth}
	for _, k := range sortedKeys(m.m) {
		if v := m.m[k]; v == nil {
			if !e.hide(k) {
				_ = enc.AddReflected(k, v)
			}
		} else if !e.hide(k) {
			// A []string holds no keys, so it is encoded directly.
			if err := enc.AddArray(k, stringArray(v)); err != nil {
				return err
			}
		}
	}
	return nil
}

type stringArray []string

func (s stringArray) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for _, v := range s {
		enc.AppendString(v)
	}
	return nil
}

type sliceAny struct {
	r     *redactor
	s     []any
	depth int
}

func (s sliceAny) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	e := &arrayEncoder{ArrayEncoder: enc, r: s.r, depth: s.depth}
	for _, v := range s.s {
		if err := e.AppendReflected(v); err != nil {
			return err
		}
	}
	return nil
}

// reflectMap handles maps with string-kind keys and arbitrary values.
type reflectMap struct {
	r     *redactor
	m     reflect.Value
	depth int
}

func (m reflectMap) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	e := &objectEncoder{r: m.r, enc: enc, depth: m.depth}
	keys := m.m.MapKeys()
	slices.SortFunc(keys, func(a, b reflect.Value) int { return strings.Compare(a.String(), b.String()) })
	for _, k := range keys {
		if err := addAny(e, k.String(), m.m.MapIndex(k).Interface()); err != nil {
			return err
		}
	}
	return nil
}

// reflectSlice handles slices and arrays whose elements may hold keys.
type reflectSlice struct {
	r     *redactor
	s     reflect.Value
	depth int
}

func (s reflectSlice) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	e := &arrayEncoder{ArrayEncoder: enc, r: s.r, depth: s.depth}
	for i := 0; i < s.s.Len(); i++ {
		if err := e.AppendReflected(s.s.Index(i).Interface()); err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
