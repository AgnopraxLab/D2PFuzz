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
	"time"

	"golang.org/x/exp/rand"

	"github.com/AgnopraxLab/D2PFuzz/fuzzer"
)

// RunFullBench runs a full benchmark with N runs.
func RunFullBench(N int) {
	time, err := testExcution(N)
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

// testExcution excution a fuzzer.
func testExcution(N int) (time.Duration, error) {
	rnd := make([]byte, 40)
	if _, err := rand.Read(rnd); err != nil {
		return 0, err
	}
	start := time.Now()
	for i := 0; i < N; i++ {
		fuzzer.Fuzz(rnd)
	}
	return time.Since(start), nil
}
