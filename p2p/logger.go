package p2p

import (
	"fmt"
	"log"
	"os"
	"time"
)

// LogLevel represents the logging level
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelError
)

// SimpleLogger is a simple implementation of the Logger interface
type SimpleLogger struct {
	level  LogLevel
	logger *log.Logger
}

// NewSimpleLogger creates a new simple logger
func NewSimpleLogger(level LogLevel) *SimpleLogger {
	return &SimpleLogger{
		level:  level,
		logger: log.New(os.Stdout, "", 0),
	}
}

// Debug logs a debug message
func (l *SimpleLogger) Debug(msg string, args ...interface{}) {
	if l.level <= LogLevelDebug {
		l.log("DEBUG", msg, args...)
	}
}

// Info logs an info message
func (l *SimpleLogger) Info(msg string, args ...interface{}) {
	if l.level <= LogLevelInfo {
		l.log("INFO", msg, args...)
	}
}

// Error logs an error message
func (l *SimpleLogger) Error(msg string, args ...interface{}) {
	if l.level <= LogLevelError {
		l.log("ERROR", msg, args...)
	}
}

func (l *SimpleLogger) log(level, msg string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	formattedMsg := fmt.Sprintf(msg, args...)
	l.logger.Printf("[%s] %s: %s", timestamp, level, formattedMsg)
}