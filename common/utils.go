package common

import (
	"D2PFuzz/fuzzing"
	"github.com/urfave/cli/v2"
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
