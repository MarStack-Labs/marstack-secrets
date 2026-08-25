package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"INFO":  slog.LevelInfo,
		" warn": slog.LevelWarn,
		"error": slog.LevelError,
	}
	for input, want := range cases {
		got, err := ParseLevel(input)
		if err != nil {
			t.Fatalf("ParseLevel(%q) returned error: %v", input, err)
		}
		if got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestParseLevelRejectsUnknown(t *testing.T) {
	if _, err := ParseLevel("verbose"); err == nil {
		t.Fatal("expected an error for an unknown level")
	}
}

func TestNewWritesJSONAndHonoursLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := New("warn", &buf)

	logger.Info("dropped")
	if buf.Len() != 0 {
		t.Fatalf("info record should be filtered out at warn level, got %q", buf.String())
	}

	logger.Warn("kept", "key", "value")
	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("log output is not valid JSON: %v", err)
	}
	if record["msg"] != "kept" || record["key"] != "value" {
		t.Errorf("unexpected record: %v", record)
	}
}

func TestNewFallsBackToInfoOnBadLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := New("nonsense", &buf)

	logger.Debug("dropped")
	if buf.Len() != 0 {
		t.Fatalf("debug should be filtered out by the info fallback, got %q", buf.String())
	}

	logger.Info("kept")
	if buf.Len() == 0 {
		t.Fatal("info should be emitted by the info fallback")
	}
}
