package loggen

import (
	"errors"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want error
	}{
		{"zero", Config{}, nil},
		{"production", ProductionConfig("s"), nil},
		{"development", DevelopmentConfig("s"), nil},
		{"bad format", Config{Format: "xml"}, ErrInvalidFormat},
		{"level too low", Config{Level: DebugLevel - 1}, ErrInvalidLevel},
		{"level too high", Config{Level: FatalLevel + 1}, ErrInvalidLevel},
		{"zero tick", Config{Sampling: &SamplingConfig{Initial: 1}}, ErrInvalidSampling},
		{"zero initial", Config{Sampling: &SamplingConfig{Tick: time.Second}}, ErrInvalidSampling},
		{"negative thereafter", Config{Sampling: &SamplingConfig{Tick: time.Second, Initial: 1, Thereafter: -1}}, ErrInvalidSampling},
		{"empty key", Config{Redaction: RedactionConfig{Keys: []string{"_-"}}}, ErrInvalidRedaction},
		{"empty substring", Config{Redaction: RedactionConfig{Substrings: []string{""}}}, ErrInvalidRedaction},
		{"replace with nothing", Config{Redaction: RedactionConfig{ReplaceDefaults: true}}, ErrInvalidRedaction},
		{"disabled ignores keys", Config{Redaction: RedactionConfig{Disabled: true, Keys: []string{""}}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if !errors.Is(err, tt.want) || (tt.want == nil) != (err == nil) {
				t.Fatalf("Validate() = %v, want %v", err, tt.want)
			}
			l, nerr := New(tt.cfg)
			if (nerr == nil) != (err == nil) || (nerr == nil) != (l != nil) {
				t.Fatalf("New() = %v, %v; Validate() = %v", l, nerr, err)
			}
		})
	}
}

func TestParseLevel(t *testing.T) {
	if lvl, err := ParseLevel("WARN"); err != nil || lvl != WarnLevel {
		t.Errorf("ParseLevel(WARN) = %v, %v", lvl, err)
	}
	if _, err := ParseLevel("loud"); !errors.Is(err, ErrInvalidLevel) {
		t.Errorf("ParseLevel(loud) err = %v", err)
	}
}

func TestPresets(t *testing.T) {
	p := ProductionConfig("api")
	if p.Format != FormatJSON || p.Level != InfoLevel || p.Sampling == nil || p.Development {
		t.Errorf("ProductionConfig = %+v", p)
	}
	d := DevelopmentConfig("api")
	if d.Format != FormatConsole || d.Level != DebugLevel || d.Sampling != nil || !d.Development {
		t.Errorf("DevelopmentConfig = %+v", d)
	}
	if _, err := NewProduction("api"); err != nil {
		t.Error(err)
	}
	if _, err := NewDevelopment("api"); err != nil {
		t.Error(err)
	}
}
