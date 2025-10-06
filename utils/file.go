package utils

import (
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common"
)

// WriteHashesToFile writes transaction hashes to the specified file
// The first hash overwrites the file, subsequent hashes are appended to the end of the file
func WriteHashesToFile(hashes []common.Hash, filename string) error {
	if len(hashes) == 0 {
		return nil
	}

	// First hash overwrites the file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", filename, err)
	}

	// Write the first hash
	_, err = file.WriteString(hashes[0].Hex() + "\n")
	if err != nil {
		file.Close()
		return fmt.Errorf("failed to write first hash: %v", err)
	}
	file.Close()

	// If there are more hashes, write them in append mode
	if len(hashes) > 1 {
		file, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open file for append: %v", err)
		}
		defer file.Close()

		for i := 1; i < len(hashes); i++ {
			_, err = file.WriteString(hashes[i].Hex() + "\n")
			if err != nil {
				return fmt.Errorf("failed to write hash %d: %v", i, err)
			}
		}
	}

	return nil
}

// AppendToFile appends content to file
func AppendToFile(filename, content string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	return err
}

// WriteStringToFile writes string content to a file (overwrites if exists)
func WriteStringToFile(filename, content string) error {
	return os.WriteFile(filename, []byte(content), 0644)
}

// InitHashFile initializes a hash file with a node name header
func InitHashFile(filename, nodeName string) error {
	header := fmt.Sprintf("# %s\n", nodeName)
	return WriteStringToFile(filename, header)
}

// AppendHashToFile appends a single hash to the file
func AppendHashToFile(filename string, hash common.Hash) error {
	hashLine := fmt.Sprintf("%s\n", hash.Hex())
	return AppendToFile(filename, hashLine)
}

// FileExists checks if a file exists
func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

// EnsureDir ensures a directory exists, creates it if it doesn't
func EnsureDir(dirPath string) error {
	if !FileExists(dirPath) {
		return os.MkdirAll(dirPath, 0755)
	}
	return nil
}

