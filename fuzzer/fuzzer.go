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
	"io/ioutil"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/crypto/sha3"
)

var (
	outputDir      = "TraceOut"
	EnvKey         = "FUZZYDIR"
	globalV4Stats  = make(map[string]*UDPPacketStats)
	globalV5Stats  = make(map[string]*UDPPacketStats)
	globalEthStats = make(map[string]*UDPPacketStats)
)

type UDPPacketStats struct {
	ExecuteCount      int // Execute count
	CheckTrueFail     int // First type of exception: Check is true but Success is false
	CheckFalsePass    int // Second type of exception: Check is false but Success is true
	CheckFalsePassOK  int
	CheckFalsePassBad int
	CheckTruePass     int // Third type of exception: Check is true but Success is true
}

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
func RunFuzzer(protocol, target, chainDir string, engine int, threads int) error {
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

func discv4Fuzzer(engine int, target string) error {
	testMaker := NewV4Maker(target)
	if testMaker == nil {
		return fmt.Errorf("failed to create V4Maker")
	}
	startTime := time.Now()

	// Channel to listen for interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Ensure resources are cleaned up when function returns
	defer func() {
		testMaker.Close()
		saveV4PacketSeed(testMaker) // Ensure seeds are saved in any case
		signal.Stop(sigChan)        // Stop signal listening
	}()

	// Separate goroutine for handling signals
	done := make(chan struct{})
	go func() {
		select {
		case <-sigChan:
			fmt.Println("\nReceived interrupt signal, saving PacketSeed and exiting...")
			close(done)
		case <-done:
			// Normal exit case
		}
	}()

	hashed := hash(testMaker.ToGeneralStateTest("hashName"))
	finalName := fmt.Sprintf("FuzzD2P-%v", common.Bytes2Hex(hashed))

	var traceFile *os.File
	if ShouldTrace {
		traceFile = setupTrace(finalName)
		defer traceFile.Close()
	}
	var err error

	fmt.Println("Discv4 protocol Fuzzing start!!!")
	if engine == 1 {
		if err = testMaker.Start(traceFile); err != nil {
			return err
		}
	} else {
		// seed init
		fmt.Println("Seed init...")
		for _, packetType := range v4options {
			req := testMaker.Client.GenPacket(packetType, testMaker.TargetList[0])
			testMaker.PakcetSeed = append(testMaker.PakcetSeed, req)
			globalV4Stats[req.Name()] = &UDPPacketStats{0, 0, 0, 0, 0, 0}
		}

		// for seed
		itration := 1
		for {
			select {
			case <-done:
				return nil
			default:
				// Original loop logic
				randomIndex := rand.Intn(len(testMaker.PakcetSeed))
				seed := testMaker.PakcetSeed[randomIndex]
				elapsed := time.Since(startTime)
				fmt.Printf("[%s] Round %d of testing, seed queue: %d, now seed type: %s\n",
					elapsed.Round(time.Second),
					itration,
					len(testMaker.PakcetSeed),
					seed.Name())
				if err = testMaker.PacketStart(traceFile, seed, globalV4Stats[seed.Name()]); err != nil {
					return err
				}
				globalV4Stats[seed.Name()].ExecuteCount = globalV4Stats[seed.Name()].ExecuteCount + 1
				for name, stats := range globalV4Stats {
					fmt.Printf("Packet: %s, Executed: %d, CheckTrueFail: %d, CheckFalsePass: %d, CheckTruePass: %d\n",
						name, stats.ExecuteCount, stats.CheckTrueFail, stats.CheckFalsePass, stats.CheckTruePass)
				}
				itration = itration + 1
			}
		}
	}

	return nil
}

func saveV4PacketSeed(testMaker *V4Maker) {
	savePath := filepath.Join(OutputDir, "discv4")
	if err := os.MkdirAll(savePath, 0755); err != nil {
		fmt.Printf("Failed to create directory: %v\n", err)
		return
	}

	filename := filepath.Join(savePath, fmt.Sprintf("%s-seed.json", time.Now().Format("2006-01-02_15-04-05")))
	seeds := make([]map[string]interface{}, 0, len(testMaker.PakcetSeed))

	for _, seed := range testMaker.PakcetSeed {
		seedMap := map[string]interface{}{
			"type": seed.Name(),
			"data": seed,
		}
		seeds = append(seeds, seedMap)
	}

	data, err := json.MarshalIndent(seeds, "", "    ")
	if err != nil {
		fmt.Printf("Failed to marshal seeds: %v\n", err)
		return
	}

	if err := ioutil.WriteFile(filename, data, 0644); err != nil {
		fmt.Printf("Failed to save seeds: %v\n", err)
		return
	}
	fmt.Printf("Seeds saved to: %s\n", filename)
}

func discv5Fuzzer(engine int, target string) error {
	testMaker := NewV5Maker(target)
	if testMaker == nil {
		return fmt.Errorf("failed to create V4Maker")
	}
	startTime := time.Now()

	// Channel to listen for interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Ensure resources are cleaned up when function returns
	defer func() {
		testMaker.Close()
		saveV5PacketSeed(testMaker) // Ensure seeds are saved in any case
		signal.Stop(sigChan)        // Stop signal listening
	}()

	// Separate goroutine for handling signals
	done := make(chan struct{})
	go func() {
		select {
		case <-sigChan:
			fmt.Println("\nReceived interrupt signal, saving PacketSeed and exiting...")
			close(done)
		case <-done:
			// Normal exit case
		}
	}()

	hashed := hash(testMaker.ToGeneralStateTest("hashName"))
	finalName := fmt.Sprintf("FuzzD2P-%v", common.Bytes2Hex(hashed))

	var traceFile *os.File
	if ShouldTrace {
		traceFile = setupTrace(finalName)
		defer traceFile.Close()
	}
	var err error

	fmt.Println("Discv5 protocol Fuzzing start!!!")
	if engine == 1 {
		if err = testMaker.Start(traceFile); err != nil {
			return err
		}
	} else {
		// seed init
		fmt.Println("Seed init...")
		for _, packetType := range v5options {
			req := testMaker.Client.GenPacket(packetType, testMaker.TargetList[0])
			testMaker.PakcetSeed = append(testMaker.PakcetSeed, req)
			globalV5Stats[req.Name()] = &UDPPacketStats{0, 0, 0, 0, 0, 0}
		}

		// for seed
		itration := 1
		for {
			select {
			case <-done:
				return nil
			default:
				// Original loop logic
				randomIndex := rand.Intn(len(testMaker.PakcetSeed))
				seed := testMaker.PakcetSeed[randomIndex]
				elapsed := time.Since(startTime)
				fmt.Printf("[%s] Round %d of testing, seed queue: %d, now seed type: %s\n",
					elapsed.Round(time.Second),
					itration,
					len(testMaker.PakcetSeed),
					seed.Name())
				if err = testMaker.PacketStart(traceFile, seed, globalV5Stats[seed.Name()]); err != nil {
					return err
				}
				globalV5Stats[seed.Name()].ExecuteCount = globalV5Stats[seed.Name()].ExecuteCount + 1
				for name, stats := range globalV5Stats {
					fmt.Printf("Packet: %s, Executed: %d, CheckTrueFail: %d, CheckFalsePass: %d, CheckTruePass: %d\n",
						name, stats.ExecuteCount, stats.CheckTrueFail, stats.CheckFalsePass, stats.CheckTruePass)
				}
				itration = itration + 1
			}
		}
	}

	return nil
}

func saveV5PacketSeed(testMaker *V5Maker) {
	savePath := filepath.Join(OutputDir, "discv5")
	if err := os.MkdirAll(savePath, 0755); err != nil {
		fmt.Printf("Failed to create directory: %v\n", err)
		return
	}

	filename := filepath.Join(savePath, fmt.Sprintf("%s-seed.json", time.Now().Format("2006-01-02_15-04-05")))
	seeds := make([]map[string]interface{}, 0, len(testMaker.PakcetSeed))

	for _, seed := range testMaker.PakcetSeed {
		seedMap := map[string]interface{}{
			"type": seed.Name(),
			"data": seed,
		}
		seeds = append(seeds, seedMap)
	}

	data, err := json.MarshalIndent(seeds, "", "    ")
	if err != nil {
		fmt.Printf("Failed to marshal seeds: %v\n", err)
		return
	}

	if err := ioutil.WriteFile(filename, data, 0644); err != nil {
		fmt.Printf("Failed to save seeds: %v\n", err)
		return
	}
	fmt.Printf("Seeds saved to: %s\n", filename)
}

func ethFuzzer(engine int, target, chain string) error {
	testMaker := NewEthMaker(target, chain)
	if testMaker == nil {
		return fmt.Errorf("failed to create V4Maker")
	}
	startTime := time.Now()

	// Channel to listen for interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Ensure resources are cleaned up when function returns
	defer func() {
		testMaker.SuiteList[0].Close()
		saveEthPacketSeed(testMaker) // Ensure seeds are saved in any case
		signal.Stop(sigChan)         // Stop signal listening
	}()

	// Separate goroutine for handling signals
	done := make(chan struct{})
	go func() {
		select {
		case <-sigChan:
			fmt.Println("\nReceived interrupt signal, saving PacketSeed and exiting...")
			close(done)
		case <-done:
			// Normal exit case
		}
	}()

	hashed := hash(testMaker.ToGeneralStateTest("hashName"))
	finalName := fmt.Sprintf("FuzzD2P-%v", common.Bytes2Hex(hashed))

	var traceFile *os.File
	if ShouldTrace {
		traceFile = setupTrace(finalName)
		defer traceFile.Close()
	}
	var err error

	fmt.Println("Eth protocol Fuzzing start!!!")
	if engine == 1 {
		if err = testMaker.Start(traceFile); err != nil {
			return err
		}
	} else {
		// seed init
		fmt.Println("Seed init...")
		for _, packetType := range ethoptions {
			req, err := testMaker.SuiteList[0].GenPacket(packetType)
			if err != nil {
				fmt.Printf("Packet generate failed: %v\n", err)
				return err
			}
			testMaker.PakcetSeed = append(testMaker.PakcetSeed, req)
			globalEthStats[req.Name()] = &UDPPacketStats{0, 0, 0, 0, 0, 0}
		}

		// for seed
		itration := 1
		for {
			select {
			case <-done:
				return nil
			default:
				// Original loop logic
				randomIndex := rand.Intn(len(testMaker.PakcetSeed))
				seed := testMaker.PakcetSeed[randomIndex]
				elapsed := time.Since(startTime)
				fmt.Printf("[%s] Round %d of testing, seed queue: %d, now seed type: %s\n",
					elapsed.Round(time.Second),
					itration,
					len(testMaker.PakcetSeed),
					seed.Name())
				if err = testMaker.PacketStart(traceFile, seed, globalEthStats[seed.Name()]); err != nil {
					return err
				}
				globalEthStats[seed.Name()].ExecuteCount = globalEthStats[seed.Name()].ExecuteCount + 1
				for name, stats := range globalEthStats {
					fmt.Printf("Packet: %s, Executed: %d, CheckTrueFail: %d, CheckFalsePass: %d, CheckTruePass: %d\n",
						name, stats.ExecuteCount, stats.CheckTrueFail, stats.CheckFalsePass, stats.CheckTruePass)
				}
				itration = itration + 1
			}
		}
	}

	return nil
}

func saveEthPacketSeed(testMaker *EthMaker) {
	savePath := filepath.Join(OutputDir, "eth")
	if err := os.MkdirAll(savePath, 0755); err != nil {
		fmt.Printf("Failed to create directory: %v\n", err)
		return
	}

	filename := filepath.Join(savePath, fmt.Sprintf("%s-seed.json", time.Now().Format("2006-01-02_15-04-05")))
	seeds := make([]map[string]interface{}, 0, len(testMaker.PakcetSeed))

	for _, seed := range testMaker.PakcetSeed {
		seedMap := map[string]interface{}{
			"type": seed.Name(),
			"data": seed,
		}
		seeds = append(seeds, seedMap)
	}

	data, err := json.MarshalIndent(seeds, "", "    ")
	if err != nil {
		fmt.Printf("Failed to marshal seeds: %v\n", err)
		return
	}

	if err := ioutil.WriteFile(filename, data, 0644); err != nil {
		fmt.Printf("Failed to save seeds: %v\n", err)
		return
	}
	fmt.Printf("Seeds saved to: %s\n", filename)
}

func hash(test *GeneralStateTest) []byte {
	h := sha3.New256()
	encoder := json.NewEncoder(h)
	if err := encoder.Encode(test); err != nil {
		panic(fmt.Sprintf("Could not hash state test: %v", err))
	}
	return h.Sum(nil)
}
