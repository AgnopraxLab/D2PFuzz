package common

import (
	"D2PFuzz/fuzzing"
	"bufio"
	"fmt"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/urfave/cli/v2"
	"os"
)

var (
	VerbosityFlag = &cli.IntFlag{
		Name:  "verbosity",
		Usage: "sets the verbosity level (-4: DEBUG, 0: INFO, 4: WARN, 8: ERROR)",
		Value: 0,
	}
)

type GeneratorFn func() *fuzzing.CliMaker

func GenerateAndExecute(c *cli.Context, generatorFn GeneratorFn) error {

	return nil
}

func GetList(fName string) ([]*enode.Node, error) {
	file, err := os.Open(fName)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	var nodeList []*enode.Node

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		node := enode.MustParse(line)
		if err != nil {
			return nil, fmt.Errorf("failed to parse enode: %v", err)
		}
		nodeList = append(nodeList, node)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	return nodeList, nil
}
