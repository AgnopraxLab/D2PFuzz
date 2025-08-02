package p2p

import (
	"github.com/stretchr/testify/mock"
)

// MockLogger is a mock implementation of Logger interface for testing
type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Debug(msg string, args ...interface{}) {
	m.Called(msg, args)
}

func (m *MockLogger) Info(msg string, args ...interface{}) {
	m.Called(msg, args)
}

func (m *MockLogger) Error(msg string, args ...interface{}) {
	m.Called(msg, args)
}