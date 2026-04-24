// Copyright 2025 CompliK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package logger provides a flexible, high-performance logging system with support for
// structured logging, multiple output formats (text/JSON), log levels, colored output,
// and contextual information tracking.
package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// LogLevel represents the severity level of a log message
type LogLevel int

const (
	DebugLevel LogLevel = iota
	InfoLevel
	WarnLevel
	ErrorLevel
	FatalLevel
)

var (
	logLevelNames = map[LogLevel]string{
		DebugLevel: "DEBUG",
		InfoLevel:  "INFO",
		WarnLevel:  "WARN",
		ErrorLevel: "ERROR",
		FatalLevel: "FATAL",
	}

	logLevelColors = map[LogLevel]string{
		DebugLevel: "\033[36m", // Cyan
		InfoLevel:  "\033[32m", // Green
		WarnLevel:  "\033[33m", // Yellow
		ErrorLevel: "\033[31m", // Red
		FatalLevel: "\033[35m", // Magenta
	}

	resetColor = "\033[0m"
)

// Fields represents a map of structured logging fields
type Fields map[string]any

// Logger is the main logging interface providing methods for different log levels
// and contextual logging capabilities
type Logger interface {
	Debug(msg string, fields ...Fields)
	Info(msg string, fields ...Fields)
	Warn(msg string, fields ...Fields)
	Error(msg string, fields ...Fields)
	Fatal(msg string, fields ...Fields)

	WithField(key string, value any) Logger
	WithFields(fields Fields) Logger
	WithContext(ctx context.Context) Logger
	WithError(err error) Logger

	SetLevel(level LogLevel)
	SetOutput(w io.Writer)
}

// StandardLogger is the default implementation of the Logger interface
type StandardLogger struct {
	mu         sync.RWMutex
	level      LogLevel
	output     io.Writer
	fields     Fields
	colored    bool
	jsonFormat bool
	showCaller bool
	timeFormat string
}

// globalLogger is the global logger instance
var (
	globalLogger *StandardLogger
	once         sync.Once
)

// Init initializes the global logger instance with default settings
func Init() {
	once.Do(func() {
		globalLogger = &StandardLogger{
			level:      InfoLevel,
			output:     os.Stdout,
			fields:     make(Fields),
			colored:    true,
			jsonFormat: false,
			showCaller: true,
			timeFormat: "2006-01-02 15:04:05.000",
		}

		// Configure from environment variables
		configureFromEnv()
	})
}

// configureFromEnv configures the logger from environment variables
func configureFromEnv() {
	// Log level
	if level := os.Getenv("COMPLIK_LOG_LEVEL"); level != "" {
		switch strings.ToUpper(level) {
		case "DEBUG":
			globalLogger.SetLevel(DebugLevel)
		case "INFO":
			globalLogger.SetLevel(InfoLevel)
		case "WARN":
			globalLogger.SetLevel(WarnLevel)
		case "ERROR":
			globalLogger.SetLevel(ErrorLevel)
		case "FATAL":
			globalLogger.SetLevel(FatalLevel)
		}
	}

	// Log format
	if format := os.Getenv("COMPLIK_LOG_FORMAT"); format == "json" {
		globalLogger.jsonFormat = true
		globalLogger.colored = false
	}

	// Enable/disable colored output
	if colored := os.Getenv("COMPLIK_LOG_COLORED"); colored == "false" {
		globalLogger.colored = false
	}

	// Enable/disable caller information
	if caller := os.Getenv("COMPLIK_LOG_CALLER"); caller == "false" {
		globalLogger.showCaller = false
	}

	// Log file output
	if logFile := os.Getenv("COMPLIK_LOG_FILE"); logFile != "" {
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o666)
		if err == nil {
			globalLogger.SetOutput(file)
			globalLogger.colored = false // Disable colors for file output
		}
	}
}

// GetLogger returns the global logger instance
func GetLogger() Logger {
	if globalLogger == nil {
		Init()
	}
	return globalLogger
}

// New creates a new logger instance with default settings
func New() Logger {
	return &StandardLogger{
		level:      InfoLevel,
		output:     os.Stdout,
		fields:     make(Fields),
		colored:    true,
		jsonFormat: false,
		showCaller: true,
		timeFormat: "2006-01-02 15:04:05.000",
	}
}

// SetLevel sets the minimum log level for this logger
func (l *StandardLogger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.level = level
}

// SetOutput sets the output destination for this logger
func (l *StandardLogger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.output = w
}

// WithField adds a single field to the logger and returns a new logger instance
func (l *StandardLogger) WithField(key string, value any) Logger {
	return l.WithFields(Fields{key: value})
}

// WithFields adds multiple fields to the logger and returns a new logger instance
func (l *StandardLogger) WithFields(fields Fields) Logger {
	l.mu.RLock()
	defer l.mu.RUnlock()

	newFields := make(Fields, len(l.fields)+len(fields))
	maps.Copy(newFields, l.fields)

	maps.Copy(newFields, fields)

	return &StandardLogger{
		level:      l.level,
		output:     l.output,
		fields:     newFields,
		colored:    l.colored,
		jsonFormat: l.jsonFormat,
		showCaller: l.showCaller,
		timeFormat: l.timeFormat,
	}
}

// WithContext adds context information to the logger and returns a new logger instance
func (l *StandardLogger) WithContext(ctx context.Context) Logger {
	l.mu.RLock()
	defer l.mu.RUnlock()

	newLogger := &StandardLogger{
		level:      l.level,
		output:     l.output,
		fields:     make(Fields, len(l.fields)),
		colored:    l.colored,
		jsonFormat: l.jsonFormat,
		showCaller: l.showCaller,
		timeFormat: l.timeFormat,
	}

	maps.Copy(newLogger.fields, l.fields)

	// Extract request ID and trace ID from context
	if ctx != nil {
		if requestID := ctx.Value("request_id"); requestID != nil {
			newLogger.fields["request_id"] = requestID
		}

		if traceID := ctx.Value("trace_id"); traceID != nil {
			newLogger.fields["trace_id"] = traceID
		}
	}

	return newLogger
}

// WithError adds error information to the logger and returns a new logger instance
func (l *StandardLogger) WithError(err error) Logger {
	if err == nil {
		return l
	}
	return l.WithField("error", err.Error())
}

// Debug logs a message at Debug level
func (l *StandardLogger) Debug(msg string, fields ...Fields) {
	l.log(DebugLevel, msg, fields...)
}

// Info logs a message at Info level
func (l *StandardLogger) Info(msg string, fields ...Fields) {
	l.log(InfoLevel, msg, fields...)
}

// Warn logs a message at Warn level
func (l *StandardLogger) Warn(msg string, fields ...Fields) {
	l.log(WarnLevel, msg, fields...)
}

// Error logs a message at Error level
func (l *StandardLogger) Error(msg string, fields ...Fields) {
	l.log(ErrorLevel, msg, fields...)
}

// Fatal logs a message at Fatal level and exits the program
func (l *StandardLogger) Fatal(msg string, fields ...Fields) {
	l.log(FatalLevel, msg, fields...)
	os.Exit(1)
}

// log is the core logging method that handles message formatting and output
func (l *StandardLogger) log(level LogLevel, msg string, extraFields ...Fields) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if level < l.level {
		return
	}

	// Merge fields
	fields := make(Fields, len(l.fields))
	maps.Copy(fields, l.fields)

	for _, f := range extraFields {
		maps.Copy(fields, f)
	}

	// Add base fields
	fields["time"] = time.Now().Format(l.timeFormat)
	fields["level"] = logLevelNames[level]
	fields["msg"] = msg

	// Add caller information
	if l.showCaller {
		if pc, file, line, ok := runtime.Caller(2); ok {
			funcName := runtime.FuncForPC(pc).Name()
			fields["caller"] = fmt.Sprintf("%s:%d", filepath.Base(file), line)
			fields["func"] = filepath.Base(funcName)
		}
	}

	// Format output
	var output string
	if l.jsonFormat {
		output = l.formatJSON(fields)
	} else {
		output = l.formatText(level, msg, fields)
	}

	// Write output
	fmt.Fprint(l.output, output)
}

// formatJSON formats the log entry as JSON
func (l *StandardLogger) formatJSON(fields Fields) string {
	data, err := json.Marshal(fields)
	if err != nil {
		return fmt.Sprintf(`{"error":"failed to marshal log: %v"}\n`, err)
	}

	return string(data) + "\n"
}

// formatText formats the log entry as human-readable text
func (l *StandardLogger) formatText(level LogLevel, msg string, fields Fields) string {
	var builder strings.Builder

	// Timestamp
	if t, ok := fields["time"].(string); ok {
		builder.WriteString(t)
		builder.WriteString(" ")
	}

	// Level (with color)
	levelStr := logLevelNames[level]
	if l.colored {
		builder.WriteString(logLevelColors[level])
		builder.WriteString(fmt.Sprintf("[%-5s]", levelStr))
		builder.WriteString(resetColor)
	} else {
		builder.WriteString(fmt.Sprintf("[%-5s]", levelStr))
	}

	builder.WriteString(" ")

	// Caller information
	if caller, ok := fields["caller"].(string); ok {
		builder.WriteString("[")
		builder.WriteString(caller)
		builder.WriteString("] ")
		delete(fields, "caller")
	}

	// Message
	builder.WriteString(msg)

	// Additional fields
	delete(fields, "time")
	delete(fields, "level")
	delete(fields, "msg")
	delete(fields, "func")

	if len(fields) > 0 {
		builder.WriteString(" | ")

		first := true
		for k, v := range fields {
			if !first {
				builder.WriteString(", ")
			}

			builder.WriteString(fmt.Sprintf("%s=%v", k, v))

			first = false
		}
	}

	builder.WriteString("\n")

	return builder.String()
}

// Global convenience methods for the default logger

func Debug(msg string, fields ...Fields) {
	GetLogger().Debug(msg, fields...)
}

func Info(msg string, fields ...Fields) {
	GetLogger().Info(msg, fields...)
}

func Warn(msg string, fields ...Fields) {
	GetLogger().Warn(msg, fields...)
}

func Error(msg string, fields ...Fields) {
	GetLogger().Error(msg, fields...)
}

func Fatal(msg string, fields ...Fields) {
	GetLogger().Fatal(msg, fields...)
}

func WithField(key string, value any) Logger {
	return GetLogger().WithField(key, value)
}

func WithFields(fields Fields) Logger {
	return GetLogger().WithFields(fields)
}

func WithContext(ctx context.Context) Logger {
	return GetLogger().WithContext(ctx)
}

func WithError(err error) Logger {
	return GetLogger().WithError(err)
}
