package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

var levels = map[string]slog.Level{
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
}

func ParseLevel(name string) (slog.Level, error) {
	level, ok := levels[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return 0, fmt.Errorf("unknown log level %q, want one of debug, info, warn, error", name)
	}
	return level, nil
}

func New(level string, w io.Writer) *slog.Logger {
	parsed, err := ParseLevel(level)
	if err != nil {
		parsed = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: parsed}))
}
