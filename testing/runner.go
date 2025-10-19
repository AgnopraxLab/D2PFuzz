package testing

import (
	"fmt"

	"github.com/AgnopraxLab/D2PFuzz/config"
)

// TestRunner defines the interface for all test modes
type TestRunner interface {
	// Name returns the test mode name
	Name() string

	// Description returns a brief description of the test
	Description() string

	// Run executes the test with the given configuration
	Run(cfg *config.Config) error
}

// Registry holds all registered test runners
var registry = make(map[string]TestRunner)

// Register registers a test runner
func Register(name string, runner TestRunner) {
	registry[name] = runner
}

// GetRunner returns a test runner by name
func GetRunner(name string) (TestRunner, bool) {
	runner, ok := registry[name]
	return runner, ok
}

// GetAllRunners returns all registered runners
func GetAllRunners() map[string]TestRunner {
	return registry
}

// ListAvailableTests prints all available test modes
func ListAvailableTests() {
	fmt.Println("Available test modes:")
	for name, runner := range registry {
		fmt.Printf("  %-25s - %s\n", name, runner.Description())
	}
}

// init registers all test runners
func init() {
	Register("single", &SingleNodeTest{})
	Register("multi", &MultiNodeTest{})
	Register("test-soft-limit", &SoftLimitTest{})
	Register("test-soft-limit-single", &SoftLimitSingleTest{})
	Register("test-soft-limit-report", &SoftLimitReportTest{})
	// Register("getPooledTxs", &GetPooledTxsTest{})
	Register("oneTransaction", &OneTransactionTest{})
	Register("largeTransactions", &LargeTransactionsTest{})

	// Blob transaction tests (EIP-4844)
	Register("blob-single", &BlobSingleNodeTest{})
	Register("blob-multi", &BlobMultiNodeTest{})
}
