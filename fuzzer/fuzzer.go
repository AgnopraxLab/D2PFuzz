package fuzzer

import (
	"D2PFuzz/config"
	"D2PFuzz/filler"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/crypto/sha3"
	"os"
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

// Fuzz is the entry point for go-fuzz
func Fuzz(data []byte) int {
	// Too little data destroys our performance and makes it hard for the generator
	if len(data) < 32 {
		return -1
	}
	f := filler.NewFiller(data)
	config, err := config.ReadConfig()
	if err != nil {
		fmt.Printf("Error reading config: %v\n", err)
		return -1
	}

	testMaker, _ := generator.GeneratePacket(f)
	name := randTestName(data)

	// minimize test

	hashed := hash(testMaker.ToGeneralStateTest("hashName"))
	finalName := fmt.Sprintf("FuzzyVM-%v", common.Bytes2Hex(hashed))
	// Execute the test and write out the resulting trace
	var traceFile *os.File
	if shouldTrace {
		traceFile = setupTrace(finalName)
		defer traceFile.Close()
	}
	if err := testMaker.Fill(traceFile); err != nil {
		panic(err)
	}

	return 1
}

func setupTrace(name string) *os.File {
	path := fmt.Sprintf("%v/%v-trace.jsonl", outputDir, name)
	traceFile, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0755)
	if err != nil {
		panic("Could not write out trace file")
	}
	return traceFile
}

func hash(test *fuzzing.GeneralStateTest) []byte {
	h := sha3.New256()
	encoder := json.NewEncoder(h)
	if err := encoder.Encode(test); err != nil {
		panic(fmt.Sprintf("Could not hash state test: %v", err))
	}
	return h.Sum(nil)
}
