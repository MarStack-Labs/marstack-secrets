package ui

import (
	"embed"
	"errors"
	"log/slog"
)

const moduleName = "ui"

var ErrNoLogger = errors.New("ui: a logger is required")

//go:embed assets/index.html assets/meridian.css assets/app.css assets/app.js
var assets embed.FS

type Options struct {
	Logger *slog.Logger
}

type Module struct {
	logger *slog.Logger
}

func NewModule(opts Options) (*Module, error) {
	if opts.Logger == nil {
		return nil, ErrNoLogger
	}
	return &Module{logger: opts.Logger}, nil
}

func (m *Module) Name() string {
	return moduleName
}
