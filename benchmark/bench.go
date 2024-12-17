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

	"github.com/AgnopraxLab/D2PFuzz/fuzzer"
)

var (
	globalV4Stats = make(map[string]*fuzzer.UDPPacketStats)
	globalV5Stats = make(map[string]*fuzzer.UDPPacketStats)
)

// RunFullBench runs a full benchmark with N runs.
func RunFullBench(prot, target, chainDir, packetType string, N int, engine int) {
	time, err := testExcution(prot, target, chainDir, packetType, N, engine)
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
func testExcution(prot, target, chainDir, packetType string, N int, engine int) (time.Duration, error) {
	// var traceFile *os.File
	start := time.Now()

	for i := 0; i < N; i++ {
		switch prot {
		case "discv4":
			testMaker := fuzzer.NewV4Maker(target)
			defer testMaker.Close()
			if engine == 1 {
				testMaker.Start(os.Stdout)
			} else {
				packet := testMaker.Client.GenPacket(packetType, testMaker.TargetList[0])
				globalV4Stats[packet.Name()] = &fuzzer.UDPPacketStats{
					ExecuteCount:   0,
					CheckTrueFail:  0,
					CheckFalsePass: 0,
					CheckTruePass:  0,
				}
				testMaker.PacketStart(os.Stdout, packet, globalV4Stats[packet.Name()])
				fmt.Printf("Packet: %s, Executed: %d, CheckTrueFail: %d, CheckFalsePass: %d, CheckTruePass: %d\n",
					packet.Name(), globalV4Stats[packet.Name()].ExecuteCount, globalV4Stats[packet.Name()].CheckTrueFail, globalV4Stats[packet.Name()].CheckFalsePass, globalV4Stats[packet.Name()].CheckTruePass)
			}
		case "discv5":
			testMaker := fuzzer.NewV5Maker(target)
			defer testMaker.Close()
			if engine == 1 {
				testMaker.Start(os.Stdout)
			} else {
				packet := testMaker.Client.GenPacket(packetType, testMaker.TargetList[0])
				globalV5Stats[packet.Name()] = &fuzzer.UDPPacketStats{
					ExecuteCount:   0,
					CheckTrueFail:  0,
					CheckFalsePass: 0,
					CheckTruePass:  0,
				}
				testMaker.PacketStart(os.Stdout, packet, globalV5Stats[packet.Name()])
				fmt.Printf("Packet: %s, Executed: %d, CheckTrueFail: %d, CheckFalsePass: %d, CheckTruePass: %d\n",
					packet.Name(), globalV5Stats[packet.Name()].ExecuteCount, globalV5Stats[packet.Name()].CheckTrueFail, globalV5Stats[packet.Name()].CheckFalsePass, globalV5Stats[packet.Name()].CheckTruePass)
			}
		case "eth":
			testMaker := fuzzer.NewEthMaker(target, chainDir)
			if engine == 1 {
				testMaker.Start(os.Stdout)
			} else {
				testMaker.PacketStart(os.Stdout)
			}
		}
	}
	return time.Since(start), nil
}
