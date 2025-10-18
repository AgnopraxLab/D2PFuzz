package utils

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// parseJWTSecretFromHexString parses hexadecimal string directly
func ParseJWTSecretFromHexString(hexString string) ([]byte, error) {
	// Remove possible 0x prefix and whitespace
	hexString = strings.TrimSpace(hexString)
	if strings.HasPrefix(hexString, "0x") {
		hexString = hexString[2:]
	}

	// Convert to byte array
	jwtSecret, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}

	// Validate length
	if len(jwtSecret) != 32 {
		return nil, fmt.Errorf("invalid JWT secret length: expected 32 bytes, got %d", len(jwtSecret))
	}

	return jwtSecret, nil
}
