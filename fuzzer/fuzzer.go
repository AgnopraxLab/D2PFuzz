// Copyright 2024 Fudong and Hosen
// This file is part of the D2PFuzz library.
//
// The D2PFuzz library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The D2PFuzz library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the D2PFuzz library. If not, see <http://www.gnu.org/licenses/>.

// Package fuzzer is the entry point for go-fuzz.
package fuzzer

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/crypto/sha3"
)

var (
	outputDir   = "out"
	EnvKey      = "FUZZYDIR"
	shouldTrace = false
)

// SetFuzzyVMDir sets the output directory for FuzzyVM
// If the environment variable FUZZYDIR is set, the output directory
// will be set to that, otherwise it will be set to a temp dir (for unit tests)
func SetFuzzyVMDir() {
	if dir, ok := os.LookupEnv(EnvKey); ok {
		outputDir = dir
	} else {
		outputDir = os.TempDir()
	}
}

// Fuzz
func RunFuzzer(protocol, target, chainDir string, engine bool, threads int) error {
	var (
		wg      sync.WaitGroup
		errChan = make(chan error, threads)
	)

	// Ensure at least one thread
	if threads < 1 {
		threads = 1
	}

	// Launch specified number of goroutines
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(threadID int) {
			defer wg.Done()

			var err error
			switch protocol {
			case "discv4":
				err = discv4Fuzzer(engine, target)
			case "discv5":
				err = discv5Fuzzer(engine, target)
			case "eth":
				err = ethFuzzer(engine, target, chainDir)
			default:
				err = fmt.Errorf("unsupported protocol: %v", protocol)
			}

			if err != nil {
				errChan <- fmt.Errorf("thread %d error: %v", threadID, err)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// Collect errors
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	// If any errors occurred, return the first one
	if len(errors) > 0 {
		return errors[0]
	}

	return nil
}

func setupTrace(name string) *os.File {
	path := fmt.Sprintf("%v/%v-trace.jsonl", outputDir, name)
	traceFile, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0755)
	if err != nil {
		panic("Could not write out trace file")
	}
	return traceFile
}

func discv4Fuzzer(engine bool, target string) error {
	testMaker := NewV4Maker(target)

	// Ensure resources are released after testMaker usage
	defer testMaker.Close()

	hashed := hash(testMaker.ToGeneralStateTest("hashName"))
	finalName := fmt.Sprintf("FuzzD2P-%v", common.Bytes2Hex(hashed))
	// Execute the test and write out the resulting trace
	var traceFile *os.File
	if shouldTrace {
		traceFile = setupTrace(finalName)
		defer traceFile.Close()
	}
	var err error
	if engine {
		err = testMaker.Start(traceFile)
	} else {
		err = testMaker.PacketStart(traceFile)
	}
	if err != nil {
		panic(err)
	}
	// Save the test

	return nil
}

func discv5Fuzzer(engine bool, target string) error {
	testMaker := NewV5Maker(target)

	// Ensure resources are released after testMaker usage
	defer testMaker.Close()

	hashed := hash(testMaker.ToGeneralStateTest("hashName"))
	finalName := fmt.Sprintf("FuzzD2P-%v", common.Bytes2Hex(hashed))
	// Execute the test and write out the resulting trace
	var traceFile *os.File
	if shouldTrace {
		traceFile = setupTrace(finalName)
		defer traceFile.Close()
	}
	var err error
	if engine {
		err = testMaker.Start(traceFile)
	} else {
		err = testMaker.PacketStart(traceFile)
	}
	if err != nil {
		panic(err)
	}
	// Save the test

	return nil
}

func ethFuzzer(engine bool, target, chain string) error {
	testMaker := NewEthMaker(target, chain)

	hashed := hash(testMaker.ToGeneralStateTest("hashName"))
	finalName := fmt.Sprintf("FuzzD2P-%v", common.Bytes2Hex(hashed))
	// Execute the test and write out the resulting trace
	var traceFile *os.File
	if shouldTrace {
		traceFile = setupTrace(finalName)
		defer traceFile.Close()
	}
	var err error
	if engine {
		err = testMaker.Start(traceFile)
	} else {
		err = testMaker.PacketStart(traceFile)
	}
	if err != nil {
		panic(err)
	}
	// Save the test

	return nil
}

func hash(test *GeneralStateTest) []byte {
	h := sha3.New256()
	encoder := json.NewEncoder(h)
	if err := encoder.Encode(test); err != nil {
		panic(fmt.Sprintf("Could not hash state test: %v", err))
	}
	return h.Sum(nil)
}
