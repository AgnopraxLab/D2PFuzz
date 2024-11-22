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

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/crypto/sha3"

	"github.com/AgnopraxLab/D2PFuzz/config"
	"github.com/AgnopraxLab/D2PFuzz/filler"
	"github.com/AgnopraxLab/D2PFuzz/fuzzing"
)

var (
	outputDir   = "out"
	EnvKey      = "FUZZYDIR"
	shouldTrace = true
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

// Fuzz is the entry point for go-fuzz
func Fuzz(data []byte) int {
	// Too little data destroys our performance and makes it hard for the generator
	if len(data) < 32 {
		return -1
	}
	conf, err := config.ReadConfig()
	if err != nil {
		fmt.Printf("Error reading config: %v\n", err)
		return -1
	}
	switch conf.ProtocolFlag {
	case "discv4":
		return discv4Fuzzer(data, conf.EngineFlag, conf.TargetFlag)
	case "discv5":
		return discv5Fuzzer(data, conf.EngineFlag, conf.TargetFlag)
	case "eth":
		return ethFuzzer(data, conf.EngineFlag, conf.TargetFlag, conf.ChainEnvFlag)
	default:
		fmt.Printf("Error config: %v\n", err)
		return -1
	}
}

func setupTrace(name string) *os.File {
	path := fmt.Sprintf("%v/%v-trace.jsonl", outputDir, name)
	traceFile, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0755)
	if err != nil {
		panic("Could not write out trace file")
	}
	return traceFile
}

func discv4Fuzzer(data []byte, engine bool, target string) int {
	// Too little data destroys our performance and makes it hard for the generator
	if len(data) < 32 {
		return -1
	}
	f := filler.NewFiller(data)
	testMaker := fuzzing.NewV4Maker(f, target)

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
	if err := testMaker.Start(traceFile); err != nil {
		panic(err)
	}
	// Save the test

	return -1
}

func discv5Fuzzer(data []byte, engine bool, target string) int {
	// Too little data destroys our performance and makes it hard for the generator
	if len(data) < 32 {
		return -1
	}
	f := filler.NewFiller(data)
	testMaker := fuzzing.NewV5Maker(f, target)

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
	if err := testMaker.Start(traceFile); err != nil {
		panic(err)
	}
	// Save the test

	return -1
}

func ethFuzzer(data []byte, engine bool, target, chain string) int {
	// Too little data destroys our performance and makes it hard for the generator
	if len(data) < 32 {
		return -1
	}
	f := filler.NewFiller(data)
	testMaker := fuzzing.NewEthMaker(f, target, chain)

	hashed := hash(testMaker.ToGeneralStateTest("hashName"))
	finalName := fmt.Sprintf("FuzzD2P-%v", common.Bytes2Hex(hashed))
	// Execute the test and write out the resulting trace
	var traceFile *os.File
	if shouldTrace {
		traceFile = setupTrace(finalName)
		defer traceFile.Close()
	}
	if err := testMaker.Start(traceFile); err != nil {
		panic(err)
	}
	// Save the test

	return -1
}

func hash(test *fuzzing.GeneralStateTest) []byte {
	h := sha3.New256()
	encoder := json.NewEncoder(h)
	if err := encoder.Encode(test); err != nil {
		panic(fmt.Sprintf("Could not hash state test: %v", err))
	}
	return h.Sum(nil)
}
