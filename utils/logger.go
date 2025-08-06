package utils

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Logger wraps the standard logger with file output
type Logger struct {
	*log.Logger
	file *os.File
}

// NewLogger creates a new logger that writes to both console and file
func NewLogger(logDir string) (*Logger, error) {
	// Ensure log directory exists
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Create log file with timestamp
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	logFileName := fmt.Sprintf("D2PFuzz_%s.log", timestamp)
	logFilePath := filepath.Join(logDir, logFileName)

	// Open log file
	file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	// Create multi-writer to write to both file and console
	multiWriter := io.MultiWriter(os.Stdout, file)

	// Create logger with timestamp prefix (remove Lshortfile since we handle it manually)
	logger := log.New(multiWriter, "", log.LstdFlags)

	return &Logger{
		Logger: logger,
		file:   file,
	}, nil
}

// Close closes the log file
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// logWithCaller logs a message with caller information
func (l *Logger) logWithCaller(level, format string, v ...interface{}) {
	_, file, line, ok := runtime.Caller(2)
	if ok {
		// Extract just the filename from the full path
		filename := filepath.Base(file)
		message := fmt.Sprintf(format, v...)
		// Use fixed width formatting for better alignment (20 characters for file:line)
		l.Printf("%-20s [%s] %s", fmt.Sprintf("%s:%d:", filename, line), level, message)
	} else {
		args := append([]interface{}{"", level}, v...)
		l.Printf("%-20s [%s] "+format, args...)
	}
}

// Info logs an info message
func (l *Logger) Info(format string, v ...interface{}) {
	l.logWithCaller("INFO", format, v...)
}

// Error logs an error message
func (l *Logger) Error(format string, v ...interface{}) {
	l.logWithCaller("ERROR", format, v...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, v ...interface{}) {
	l.logWithCaller("WARN", format, v...)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, v ...interface{}) {
	l.logWithCaller("DEBUG", format, v...)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(format string, v ...interface{}) {
	l.logWithCaller("FATAL", format, v...)
	os.Exit(1)
}
