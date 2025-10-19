package testing

import (
	"fmt"
	"strings"

	"github.com/AgnopraxLab/D2PFuzz/config"
	"github.com/AgnopraxLab/D2PFuzz/utils"
)

// SoftLimitTest tests all clients' soft limit implementation
type SoftLimitTest struct{}

func (t *SoftLimitTest) Name() string {
	return "test-soft-limit"
}

func (t *SoftLimitTest) Description() string {
	return "Test soft limit implementation for all clients"
}

func (t *SoftLimitTest) Run(cfg *config.Config) error {
	fmt.Println("=== D2PFuzz Test All Clients Soft Limit ===")
	return TestAllClientsSoftLimitImpl(cfg)
}

// SoftLimitSingleTest tests single client's soft limit
type SoftLimitSingleTest struct{}

func (t *SoftLimitSingleTest) Name() string {
	return "test-soft-limit-single"
}

func (t *SoftLimitSingleTest) Description() string {
	return "Test soft limit for a single client"
}

func (t *SoftLimitSingleTest) Run(cfg *config.Config) error {
	fmt.Println("=== D2PFuzz Test Single Client Soft Limit ===")

	nodeIndex := cfg.Test.SingleNodeIndex
	hashCount := 4096 // Test at soft limit
	nonceStr := cfg.Test.SingleNodeNonce

	if nodeIndex < 0 || nodeIndex >= cfg.GetNodeCount() {
		return fmt.Errorf("invalid node index: %d, valid range: 0-%d", nodeIndex, cfg.GetNodeCount()-1)
	}

	// Parse nonce value
	startNonce, _, err := utils.ParseNonceValue(nonceStr)
	if err != nil {
		return fmt.Errorf("failed to parse nonce: %w", err)
	}

	nodeName := cfg.GetNodeName(nodeIndex)
	fmt.Printf("\n========================================\n")
	fmt.Printf("Testing: %s\n", strings.ToUpper(nodeName))
	fmt.Printf("Scenario: %d items\n", hashCount)
	fmt.Printf("Starting nonce: %s -> %d\n", nonceStr, startNonce)
	fmt.Printf("========================================\n\n")

	requested, status, err := TestNewPooledTransactionHashesSoftLimitWithNonceDetailed(cfg, nodeIndex, hashCount, startNonce)
	if err != nil {
		fmt.Printf("❌ Test error: %v\n", err)
		return err
	}

	percentage := float64(requested) * 100.0 / float64(hashCount)
	symbol := "✓"
	if requested < hashCount && hashCount > 4096 {
		symbol = "⚠"
	}
	if status != "SUCCESS" {
		symbol = "❌"
	}

	fmt.Printf("\n========================================\n")
	fmt.Printf("Result: %s %d/%d (%.1f%%) [%s]\n", symbol, requested, hashCount, percentage, status)

	// Analyze result
	if status == "SUCCESS" {
		if requested == hashCount {
			if hashCount <= 4096 {
				fmt.Printf("Status: ✅ PASS - All announcements accepted (within limit)\n")
			} else {
				fmt.Printf("Status: ❌ FAIL - No soft limit enforced\n")
			}
		} else if requested == 4096 && hashCount > 4096 {
			fmt.Printf("Status: ✅ PASS - Soft limit (4096) correctly enforced\n")
		} else if requested < 4096 {
			fmt.Printf("Status: ⚠ PARTIAL - Custom limit at %d items\n", requested)
		} else {
			fmt.Printf("Status: ⚠ MIXED - Inconsistent behavior\n")
		}
	} else {
		fmt.Printf("Status: %s\n", status)
	}
	fmt.Printf("========================================\n")

	return nil
}

// SoftLimitReportTest generates soft limit test report
type SoftLimitReportTest struct{}

func (t *SoftLimitReportTest) Name() string {
	return "test-soft-limit-report"
}

func (t *SoftLimitReportTest) Description() string {
	return "Generate concise soft limit test report for all clients"
}

func (t *SoftLimitReportTest) Run(cfg *config.Config) error {
	fmt.Println("=== D2PFuzz Soft Limit Test Report ===")
	return TestSoftLimitForReportImpl(cfg)
}
