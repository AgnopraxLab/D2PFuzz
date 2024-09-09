package fuzzer

import (
	"fmt"
	"testing"

	"D2PFuzz/filler"
)

func init() {
	SetFuzzyVMDir()
}

func FuzzD2P(f *testing.F) {
	f.Fuzz(func(t *testing.T, a []byte) {
		Fuzz(a)
	})
}

func TestFuzzer(t *testing.T) {
	data := "asdfasdfasdfasdfasdfasdfasdffasdfasdfasdfasdfasd"
	Fuzz([]byte(data))
}

func TestMinimizeProgram(t *testing.T) {
	// Only local test, should not be run in test pipeline
	data := "asdfadfasdfasdfasdfasdfasdfadsfldlafdsgoinsfandofaijdsf"
	f := filler.NewFiller([]byte(data))
	testMaker, _ := generator.GenerateProgram(f)
	name := randTestName([]byte(data))
	if err := testMaker.Fill(nil); err != nil {
		panic(err)
	}
	// Save the test
	test := testMaker.ToGeneralStateTest(name)
	hashed := hash(testMaker.ToGeneralStateTest("hashName"))
	storeTest(test, hashed, name)
	// minimize
	minimized, err := minimizeProgram(testMaker, name)
	if err != nil {
		t.Error(err)
	}
	minTest := minimized.ToGeneralStateTest(name)
	_ = minTest
	fmt.Printf("%v", minTest)
	minHashed := hash(testMaker.ToGeneralStateTest("hashName"))
	storeTest(minTest, minHashed, name+"_min")
}
