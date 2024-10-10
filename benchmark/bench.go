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
package benchmark

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/exp/rand"

	"github.com/AgnopraxLab/D2PFuzz/filler"
	"github.com/AgnopraxLab/D2PFuzz/fuzzing"
)

// RunFullBench runs a full benchmark with N runs.
func RunFullBench(prot, target, chainDir string, N int) {
	time, err := testExcution(prot, target, chainDir, N)
	// Basic building blocks
	printResult("BenchmarkTestGeneration", time, err)
}

func printResult(name string, time time.Duration, err error) {
	if err != nil {
		fmt.Printf("Benchmark %v produced error: %v\n", name, err)
		return
	}
	fmt.Printf("Benchmark %v took %v \n", name, time.String())
}

func newFiller() (*filler.Filler, error) {
	rand.Seed(12345)
	rnd := make([]byte, 4000)
	if _, err := rand.Read(rnd); err != nil {
		return nil, err
	}
	return filler.NewFiller(rnd), nil
}

// testExcution excution a fuzzer.
func testExcution(prot, target, chainDir string, N int) (time.Duration, error) {
	f, err := newFiller()
	if err != nil {
		return time.Nanosecond, err
	}
	// var traceFile *os.File
	start := time.Now()
	for i := 0; i < N; i++ {
		switch prot {
		case "discv4":
			testMaker := fuzzing.NewV4Maker(f, target)
			testMaker.Start(os.Stdout)
		case "discv5":
			testMaker := fuzzing.NewV5Maker(f, target)
			testMaker.Start(os.Stdout)
		case "eth":
			testMaker := fuzzing.NewEthMaker(f, target, chainDir)
			testMaker.Start(os.Stdout)
		}
	}
	return time.Since(start), nil
}
