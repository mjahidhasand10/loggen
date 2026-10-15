package loggen

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const secret = "s3cr3t-VALUE"

type stringer string

func (s stringer) String() string { return string(s) }

type credStruct struct {
	User     string
	Password string
}

// account implements zapcore.ObjectMarshaler with nested objects/arrays.
type account struct {
	Name   string
	APIKey string
	Keys   []apiKey
}

type apiKey struct{ ID, Secret string }

func (a account) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("name", a.Name)
	enc.AddString("api_key", a.APIKey)
	enc.AddInt("n", len(a.Keys))
	return enc.AddArray("keys", zapcore.ArrayMarshalerFunc(func(ae zapcore.ArrayEncoder) error {
		for _, k := range a.Keys {
			if err := ae.AppendObject(k); err != nil {
				return err
			}
		}
		return nil
	}))
}

func (k apiKey) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("id", k.ID)
	enc.AddString("client_secret", k.Secret)
	return nil
}

// allTypes adds every ObjectEncoder method under a sensitive key.
type allTypes struct{}

func (allTypes) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddBinary("password", []byte(secret))
	enc.AddByteString("password1", []byte(secret))
	enc.AddBool("password2", true)
	enc.AddComplex128("password3", 1+2i)
	enc.AddComplex64("password4", 1+2i)
	enc.AddDuration("password5", 1)
	enc.AddFloat64("password6", 1.5)
	enc.AddFloat32("password7", 1.5)
	enc.AddInt("password8", 1)
	enc.AddInt64("password9", 1)
	enc.AddInt32("password10", 1)
	enc.AddInt16("password11", 1)
	enc.AddInt8("password12", 1)
	enc.AddString("password13", secret)
	enc.AddTime("password14", time.Unix(1, 0))
	enc.AddUint("password15", 1)
	enc.AddUint64("password16", 1)
	enc.AddUint32("password17", 1)
	enc.AddUint16("password18", 1)
	enc.AddUint8("password19", 1)
	enc.AddUintptr("password20", 1)
	_ = enc.AddReflected("password21", credStruct{Password: secret})
	_ = enc.AddObject("password22", apiKey{Secret: secret})
	_ = enc.AddArray("password23", zapcore.ArrayMarshalerFunc(func(ae zapcore.ArrayEncoder) error {
		ae.AppendString(secret)
		return nil
	}))
	enc.AddString("plain", "visible")
	return nil
}

func TestRedactEveryFieldType(t *testing.T) {
	fields := []Field{
		zap.Binary("password", []byte(secret)),
		zap.ByteString("passwd", []byte(secret)),
		zap.Bool("secret", true),
		zap.Complex128("token", 1),
		zap.Complex64("access_token", 1),
		zap.Duration("refresh_token", time.Second),
		zap.Float64("api_key", 1),
		zap.Float32("apikey", 1),
		zap.Int("x-api-key", 1),
		zap.Int64("client_secret", 1),
		zap.Int32("authorization", 1),
		zap.Int16("cookie", 1),
		zap.Int8("set-cookie", 1),
		zap.String("password_hash", secret),
		zap.Time("id_token", time.Unix(1, 0)),
		zap.Time("session_token", time.Time{}), // TimeFullType
		zap.Uint("private_key", 1),
		zap.Uint64("sessionid", 1),
		zap.Uint32("credentials", 1),
		zap.Uint16("db_password", 1),
		zap.Uint8("csrf_token", 1),
		zap.Uintptr("stripe_api_key", 1),
		zap.Reflect("pwd", credStruct{Password: secret}),
		zap.Stringer("bearer_token", stringer(secret)),
		zap.NamedError("password_err", errors.New(secret)),
		zap.Object("auth_token", apiKey{Secret: secret}),
		zap.Strings("app_secret", []string{secret}),
		zap.Any("Proxy-Authorization", secret),
		zap.ByteStrings("passwords", [][]byte{[]byte(secret)}),
	}
	l, buf := newTestLogger(t, Config{})
	l.Info("m", fields...)
	if strings.Contains(buf.String(), secret) {
		t.Fatalf("secret leaked: %s", buf.String())
	}
	e := buf.one(t)
	for _, f := range fields {
		if e[f.Key] != DefaultPlaceholder {
			t.Errorf("%s (type %d) = %v, want placeholder", f.Key, f.Type, e[f.Key])
		}
	}
}

func TestRedactAllObjectEncoderMethods(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	l.Info("m", zap.Object("obj", allTypes{}), zap.Inline(allTypes{}))
	if strings.Contains(buf.String(), secret) {
		t.Fatalf("secret leaked: %s", buf.String())
	}
	e := buf.one(t)
	obj := e["obj"].(map[string]any)
	for _, m := range []map[string]any{obj, e} {
		if len(m) < 24 || m["plain"] != "visible" {
			t.Fatalf("unexpected object: %v", m)
		}
		for k, v := range m {
			if strings.HasPrefix(k, "password") && v != DefaultPlaceholder {
				t.Errorf("%s = %v", k, v)
			}
		}
	}
}

func TestRedactNested(t *testing.T) {
	acct := account{Name: "acme", APIKey: secret, Keys: []apiKey{{"k1", secret}, {"k2", secret}}}
	l, buf := newTestLogger(t, Config{})
	l.Info("m",
		zap.Object("account", acct),
		zap.Objects("keys", []apiKey{{"k3", secret}}),
		zap.Dict("user", zap.String("name", "bob"), zap.Dict("login", zap.String("refresh_token", secret), zap.Int("ttl", 60))),
		zap.Array("nested", zapcore.ArrayMarshalerFunc(func(ae zapcore.ArrayEncoder) error {
			return ae.AppendArray(zapcore.ArrayMarshalerFunc(func(ae zapcore.ArrayEncoder) error {
				_ = ae.AppendReflected(map[string]any{"token": secret, "ok": 1})
				return ae.AppendObject(apiKey{"k4", secret})
			}))
		})),
	)
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("secret leaked: %s", out)
	}
	for _, want := range []string{
		`"account":{"name":"acme","api_key":"[REDACTED]","n":2,"keys":[{"id":"k1","client_secret":"[REDACTED]"},{"id":"k2","client_secret":"[REDACTED]"}]}`,
		`"keys":[{"id":"k3","client_secret":"[REDACTED]"}]`,
		`"user":{"name":"bob","login":{"refresh_token":"[REDACTED]","ttl":60}}`,
		`"nested":[[{"ok":1,"token":"[REDACTED]"},{"id":"k4","client_secret":"[REDACTED]"}]]`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in\n%s", want, out)
		}
	}
}

func TestRedactReflectedMaps(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+secret)
	h.Set("Cookie", "sid="+secret)
	h.Set("Accept", "text/plain")
	q := url.Values{"token": {secret}, "page": {"2"}}
	m := map[string]any{
		"z":        1,
		"a":        "x",
		"password": secret,
		"inner":    map[string]any{"api_key": secret, "list": []any{map[string]any{"secret": secret}, "v", 2.5, nil}},
		"strs":     map[string]string{"client_secret": secret, "id": "c1"},
		"rows":     []map[string]any{{"token": secret}},
		"nilmap":   map[string]any(nil),
		"b":        true,
		"i64":      int64(7),
	}

	l, buf := newTestLogger(t, Config{})
	l.Info("m", zap.Any("headers", h), zap.Any("query", q), zap.Any("data", m),
		zap.Any("vals", map[string][]string{"x-api-key": {secret}, "nil": nil}),
		zap.Any("list", []any{map[string]string{"password": secret}}))
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("secret leaked: %s", out)
	}
	for _, want := range []string{
		`"headers":{"Accept":["text/plain"],"Authorization":"[REDACTED]","Cookie":"[REDACTED]"}`,
		`"query":{"page":["2"],"token":"[REDACTED]"}`,
		// keys sorted, like encoding/json
		`"data":{"a":"x","b":true,"i64":7,"inner":{"api_key":"[REDACTED]","list":[{"secret":"[REDACTED]"},"v",2.5,null]},"nilmap":null,"password":"[REDACTED]","rows":[{"token":"[REDACTED]"}],"strs":{"client_secret":"[REDACTED]","id":"c1"},"z":1}`,
		`"vals":{"nil":null,"x-api-key":"[REDACTED]"}`,
		`"list":[{"password":"[REDACTED]"}]`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in\n%s", want, out)
		}
	}
}

func TestRedactNamespace(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	l.Info("m", zap.String("before", "ok"), zap.Namespace("credentials"), zap.String("user", secret), zap.Int("n", 1))
	l.With(zap.Namespace("secrets")).Info("m2", zap.String("anything", secret))
	l.With(zap.Namespace("request")).Info("m3", zap.String("path", "/x"), zap.String("token", secret))
	l.Info("m4", zap.Object("o", zapcore.ObjectMarshalerFunc(func(enc zapcore.ObjectEncoder) error {
		enc.AddString("visible", "ok")
		enc.OpenNamespace("login")
		enc.AddString("inside", "ok")
		enc.OpenNamespace("api_keys")
		enc.AddString("k1", secret)
		return nil
	})))
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("secret leaked: %s", out)
	}
	for _, want := range []string{
		`"before":"ok","credentials":{"user":"[REDACTED]","n":"[REDACTED]"}`,
		`"secrets":{"anything":"[REDACTED]"}`,
		`"request":{"path":"/x","token":"[REDACTED]"}`,
		`"o":{"visible":"ok","login":{"inside":"ok","api_keys":{"k1":"[REDACTED]"}}}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in\n%s", want, out)
		}
	}
}

func TestRedactPersistentAndInherited(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	base := l.With(zap.String("api_key", secret), zap.Dict("db", zap.String("password", secret), zap.String("host", "h")))
	child := base.Named("child").With(zap.String("refresh_token", secret))
	child.Info("a")
	base.Zap().With(zap.String("token", secret)).Info("b")
	base.Zap().Sugar().Infow("c", "password", secret, "user", "bob")
	child.Ctx(WithRequestID(context.Background(), "r1")).Warn("d", zap.String("secret", secret))
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Fatalf("secret leaked: %s", out)
	}
	e := buf.entries(t)
	if len(e) != 4 {
		t.Fatalf("got %d entries", len(e))
	}
	for _, x := range e {
		if x["api_key"] != DefaultPlaceholder || x["db"].(map[string]any)["host"] != "h" {
			t.Errorf("persistent field not kept/redacted: %v", x)
		}
	}
	if e[2]["user"] != "bob" || e[2]["password"] != DefaultPlaceholder {
		t.Errorf("sugared entry = %v", e[2])
	}
}

func TestRedactKeyNormalization(t *testing.T) {
	r := newRedactor(RedactionConfig{})
	for _, k := range []string{
		"password", "PASSWORD", "Password", "access_token", "AccessToken", "Access-Token",
		"ACCESS.TOKEN", "x-api-key", "X_API_KEY", "user_password", "dbPassword", "Set-Cookie",
		"jwtToken", "aws_secret_access_key", "authorization",
		strings.Repeat("x", 100) + "_password", // longer than the stack buffer
	} {
		if !r.sensitive(k) {
			t.Errorf("%q not sensitive", k)
		}
	}
	for _, k := range []string{"", "user", "username", "email", "path", "status", "pass_rate_x", "author", "request_id", "key", strings.Repeat("y", 100)} {
		if r.sensitive(k) {
			t.Errorf("%q should not be sensitive", k)
		}
	}
}

func TestRedactionConfig(t *testing.T) {
	l, buf := newTestLogger(t, Config{Redaction: RedactionConfig{
		Keys: []string{"ssn"}, Substrings: []string{"card"}, Placeholder: "***",
	}})
	l.Info("m", zap.String("SSN", "1"), zap.String("credit_card_number", "2"), zap.String("password", "3"), zap.String("name", "n"))
	e := buf.one(t)
	if e["SSN"] != "***" || e["credit_card_number"] != "***" || e["password"] != "***" || e["name"] != "n" {
		t.Errorf("custom keys: %v", e)
	}

	l, buf = newTestLogger(t, Config{Redaction: RedactionConfig{ReplaceDefaults: true, Keys: []string{"ssn"}}})
	l.Info("m", zap.String("ssn", "1"), zap.String("password", "visible"))
	e = buf.one(t)
	if e["ssn"] != DefaultPlaceholder || e["password"] != "visible" {
		t.Errorf("ReplaceDefaults: %v", e)
	}

	l, buf = newTestLogger(t, Config{Redaction: RedactionConfig{Disabled: true}})
	l.Info("m", zap.String("password", "visible"))
	if e = buf.one(t); e["password"] != "visible" {
		t.Errorf("Disabled: %v", e)
	}
}

func TestRedactDoesNotMutateCallerFields(t *testing.T) {
	r := newRedactor(RedactionConfig{})
	in := []Field{zap.String("user", "u"), zap.String("password", secret)}
	out, _ := r.fields(in, false)
	if in[1].String != secret {
		t.Error("caller's slice was modified")
	}
	if out[1].String != DefaultPlaceholder || &out[0] == &in[0] {
		t.Error("expected a redacted copy")
	}
}

func TestRedactFastPathAllocs(t *testing.T) {
	r := newRedactor(RedactionConfig{})
	fs := []Field{zap.String("user", "u"), zap.Int("status", 200), zap.Duration("latency", time.Millisecond), zap.Bool("ok", true)}
	allocs := testing.AllocsPerRun(100, func() {
		out, _ := r.fields(fs, false)
		if &out[0] != &fs[0] {
			t.Fatal("non-sensitive fields were copied")
		}
	})
	if allocs != 0 {
		t.Errorf("fast path allocs = %v, want 0", allocs)
	}
}

// The tests below pin documented limitations. If one starts failing,
// redaction got broader: update the README's "Not covered" list.

func TestLimitationMessageNotRedacted(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	l.Info("password=" + secret)
	if !strings.Contains(buf.String(), secret) {
		t.Error("message unexpectedly modified")
	}
}

func TestLimitationValuesNotScanned(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	l.Info("m", zap.String("url", "https://x/?token="+secret), zap.Error(errors.New("bad key "+secret)),
		zap.Stringer("s", stringer(secret)))
	if strings.Count(buf.String(), secret) != 3 {
		t.Errorf("values unexpectedly modified: %s", buf.String())
	}
}

func TestLimitationStructFieldsNotWalked(t *testing.T) {
	l, buf := newTestLogger(t, Config{})
	l.Info("m", zap.Any("user", credStruct{User: "bob", Password: secret}))
	if !strings.Contains(buf.String(), secret) {
		t.Error("struct fields unexpectedly redacted")
	}
}
