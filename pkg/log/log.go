package log

import (
	"context"
	"fmt"
	"log/slog"
)

// Logger is an alias for slog.Logger
type Logger = slog.Logger

var defaultLogger *Logger

// Convenience variables to match slog's API
var (
	String = slog.String
	Int    = slog.Int
	Int64  = slog.Int64
	Bool   = slog.Bool
	Any    = slog.Any
)

// Package-level logging functions
func Info(msg string, args ...any) {
	defaultLogger.Info(msg, args...)
}

func Warn(msg string, args ...any) {
	defaultLogger.Warn(msg, args...)
}

func Error(msg string, args ...any) {
	defaultLogger.Error(msg, args...)
}

func Errorf(format string, args ...any) {
	defaultLogger.Error(fmt.Sprintf(format, args...))
}

func Debug(msg string, args ...any) {
	defaultLogger.Debug(msg, args...)
}

func Err(err error) slog.Attr {
	return slog.Attr{Key: "error", Value: slog.AnyValue(err)}
}

func FilePath(path string) slog.Attr {
	return slog.Attr{Key: "file_path", Value: slog.AnyValue(path)}
}

func DirPath(path string) slog.Attr {
	return slog.Attr{Key: "dir_path", Value: slog.AnyValue(path)}
}

// PrefixHandler is a simple wrapper around slog.Handler that adds a prefix to all messages
type PrefixHandler struct {
	prefix  string
	handler slog.Handler
}

func init() {
	slog.SetLogLoggerLevel(slog.LevelDebug)
	prefixHandler := &PrefixHandler{
		prefix:  "",
		handler: slog.Default().Handler(),
	}
	defaultLogger = slog.New(prefixHandler)
}

// WithPrefix returns a new logger with the specified prefix
func WithPrefix(prefix string) *Logger {
	return slog.New(&PrefixHandler{
		prefix:  prefix,
		handler: defaultLogger.Handler(),
	})
}

func SetLogger(l *Logger) {
	defaultLogger = l
}

// Handle implements slog.Handler interface
func (h *PrefixHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.prefix != "" {
		r.Message = fmt.Sprintf("[%s] %s", h.prefix, r.Message)
	}
	return h.handler.Handle(ctx, r)
}

// WithAttrs implements slog.Handler interface
func (h *PrefixHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &PrefixHandler{
		prefix:  h.prefix,
		handler: h.handler.WithAttrs(attrs),
	}
}

// WithGroup implements slog.Handler interface
func (h *PrefixHandler) WithGroup(name string) slog.Handler {
	return &PrefixHandler{
		prefix:  h.prefix,
		handler: h.handler.WithGroup(name),
	}
}

// Enabled implements slog.Handler interface
func (h *PrefixHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}
