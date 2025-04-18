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

// PacketCoverage 存储特定包类型的覆盖率信息
type PacketCoverage struct {
	PacketType int   // 包类型
	CountSet   []int // 包含的数量集合
	DetailsSet []int // 详细信息集合（如区块编号等）
}

var (
	outputDir      = "TraceOut"
	EnvKey         = "FUZZYDIR"
	globalV4Stats  = make(map[string]*UDPPacketStats)
	globalV5Stats  = make(map[string]*UDPPacketStats)
	globalEthStats = make(map[string]*UDPPacketStats)
	StateCoverage  = []PacketCoverage{} // 状态覆盖率
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
			case "snap":
				err = snapFuzzer(engine, target, chainDir)
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

	// Create coverage recording file
	coveragePath := filepath.Join(OutputDir, "discv5")
	if err := os.MkdirAll(coveragePath, 0755); err != nil {
		fmt.Printf("Failed to create directory: %v\n", err)
	}

	// Use CSV format for easier processing
	coverageFilename := filepath.Join(coveragePath, fmt.Sprintf("%s-coverage.csv", time.Now().Format("2006-01-02_15-04-05")))
	coverageFile, coverageErr := os.OpenFile(coverageFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if coverageErr != nil {
		fmt.Printf("Failed to create coverage file: %v\n", coverageErr)
	} else {
		defer coverageFile.Close()
		// Write CSV header
		coverageFile.WriteString("time_s,coverage\n")
	}

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

	fmt.Println("Discv5 protocol Fuzzing start!!!")
	if engine == 1 {
		if err := testMaker.Start(traceFile); err != nil {
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
				if packetErr := testMaker.PacketStart(traceFile, seed, globalV5Stats[seed.Name()]); packetErr != nil {
					return packetErr
				}
				globalV5Stats[seed.Name()].ExecuteCount = globalV5Stats[seed.Name()].ExecuteCount + 1
				for name, stats := range globalV5Stats {
					fmt.Printf("Packet: %s, Executed: %d, CheckTrueFail: %d, CheckFalsePass: %d, CheckTruePass: %d\n",
						name, stats.ExecuteCount, stats.CheckTrueFail, stats.CheckFalsePass, stats.CheckTruePass)
				}

				// Record runtime and coverage (as floating point seconds)
				runtimeSec := float64(time.Since(startTime).Milliseconds()) / 1000.0
				coverageTotal := GetTotalCoverage(StateCoverage)
				coverageInfo := fmt.Sprintf("%.3f,%d\n", runtimeSec, coverageTotal)

				// Print to console with a more user-friendly format
				fmt.Printf("[%s] Runtime: %.3f seconds, State coverage: %d\n",
					time.Now().Format("2006-01-02 15:04:05"),
					runtimeSec,
					coverageTotal)

				if coverageFile != nil {
					coverageFile.WriteString(coverageInfo)
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

	// Create coverage recording file
	coveragePath := filepath.Join(OutputDir, "eth")
	if err := os.MkdirAll(coveragePath, 0755); err != nil {
		fmt.Printf("Failed to create directory: %v\n", err)
	}

	// Use CSV format for easier processing
	coverageFilename := filepath.Join(coveragePath, fmt.Sprintf("%s-coverage.csv", time.Now().Format("2006-01-02_15-04-05")))
	coverageFile, err := os.OpenFile(coverageFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Failed to create coverage file: %v\n", err)
	} else {
		defer coverageFile.Close()
		// Write CSV header
		coverageFile.WriteString("time_s,coverage\n")
	}

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

				// Record runtime and coverage (as floating point seconds)
				runtimeSec := float64(time.Since(startTime).Milliseconds()) / 1000.0
				coverageTotal := GetTotalCoverage(StateCoverage)
				coverageInfo := fmt.Sprintf("%.3f,%d\n", runtimeSec, coverageTotal)

				// Print to console with a more user-friendly format
				fmt.Printf("[%s] Runtime: %.3f seconds, State coverage: %d\n",
					time.Now().Format("2006-01-02 15:04:05"),
					runtimeSec,
					coverageTotal)

				if coverageFile != nil {
					coverageFile.WriteString(coverageInfo)
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

func snapFuzzer(engine int, target, chain string) error {
	testMaker := NewSnapMaker(target, chain)
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
		saveSnapPacketSeed(testMaker) // Ensure seeds are saved in any case
		signal.Stop(sigChan)          // Stop signal listening
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

	fmt.Println("Snap protocol Fuzzing start!!!")
	if engine == 1 {
		if err = testMaker.Start(traceFile); err != nil {
			return err
		}
	} else {
		// seed init
		fmt.Println("Seed init...")
		for _, packetType := range snapoptions {
			req, err := testMaker.SuiteList[0].GenSnapPacket(packetType)
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

				// 添加覆盖率显示
				runtimeSec := float64(time.Since(startTime).Milliseconds()) / 1000.0
				coverageTotal := GetTotalCoverage(StateCoverage)
				fmt.Printf("[%s] Runtime: %.3f seconds, State coverage: %d\n",
					time.Now().Format("2006-01-02 15:04:05"),
					runtimeSec,
					coverageTotal)

				itration = itration + 1
			}
		}
	}

	return nil
}

func saveSnapPacketSeed(testMaker *SnapMaker) {
	savePath := filepath.Join(OutputDir, "snap")
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

// updateCoverage 检查并更新覆盖率
func updateCoverage(states *[]PacketCoverage, diffCode []int) {
	// 如果差分编码为空或无效，则不处理
	if len(diffCode) <= 1 {
		return
	}

	// 忽略特殊状态码
	if diffCode[0] == NoResponse || diffCode[0] == EmptyResponse {
		return
	}

	packetType := diffCode[0]

	// 查找是否已存在该包类型的覆盖率记录
	var coverage *PacketCoverage
	var coverageIndex int

	for i := range *states {
		if (*states)[i].PacketType == packetType {
			coverage = &(*states)[i]
			coverageIndex = i
			break
		}
	}

	// 如果不存在该包类型的记录，创建新记录
	if coverage == nil {
		newCoverage := PacketCoverage{
			PacketType: packetType,
			CountSet:   []int{},
			DetailsSet: []int{},
		}
		*states = append(*states, newCoverage)
		coverage = &(*states)[len(*states)-1]
		coverageIndex = len(*states) - 1
	}

	// 如果有数量信息（至少有2个元素）
	if len(diffCode) >= 2 {
		count := diffCode[1]

		// 检查是否已存在该数量，不存在则添加
		countExists := false
		for _, c := range coverage.CountSet {
			if c == count {
				countExists = true
				break
			}
		}

		if !countExists {
			(*states)[coverageIndex].CountSet = append((*states)[coverageIndex].CountSet, count)
		}

		// 处理详细信息（从第3个元素开始）
		if len(diffCode) > 2 {
			for i := 2; i < len(diffCode); i++ {
				detail := diffCode[i]

				// 检查是否已存在该详细信息，不存在则添加
				detailExists := false
				for _, d := range coverage.DetailsSet {
					if d == detail {
						detailExists = true
						break
					}
				}

				if !detailExists {
					(*states)[coverageIndex].DetailsSet = append((*states)[coverageIndex].DetailsSet, detail)
				}
			}
		}
	}
}

// GetTotalCoverage 计算总覆盖率
func GetTotalCoverage(coverage []PacketCoverage) int {
	total := 0
	for _, cov := range coverage {
		// 包类型本身算一个
		total++
		// 加上不同的数量
		total += len(cov.CountSet)
		// 加上不同的详细信息
		total += len(cov.DetailsSet)
	}
	return total
}
