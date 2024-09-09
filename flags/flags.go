package flags

import (
	"D2PFuzz/utils"
	"github.com/urfave/cli/v2"
	"runtime"
)

var (
	SeedFlag = &cli.Int64Flag{
		Name:  "seed",
		Usage: "Seed for the RNG, (Default = RandomSeed)",
		Value: 0,
	}
	GenTestFlag = &cli.BoolFlag{
		Name:    "genTest",
		Aliases: []string{"gt"},
		Usage:   "Specify the protocol to test",
		Value:   true,
	}
	ProtocolFlag = &cli.StringFlag{
		Name:    "protocol",
		Aliases: []string{"p"},
		Usage:   "Specify the protocol to test",
		Value:   "discv4",
	}
	FileFlag = &cli.StringFlag{
		Name:    "file",
		Aliases: []string{"f"},
		Usage:   "Specify the file containing test data",
	}
	LocationFlag = &cli.StringFlag{
		Name:  "outdir",
		Usage: "Location to place artefacts",
		Value: "/tmp",
	}
	ThreadFlag = &cli.IntFlag{
		Name:  "parallel",
		Usage: "Number of parallel executions to use.",
		Value: runtime.NumCPU(),
	}
	VerbosityFlag = &cli.IntFlag{
		Name:  "verbosity",
		Usage: "sets the verbosity level (-4: DEBUG, 0: INFO, 4: WARN, 8: ERROR)",
		Value: 0,
	}
	SkipTraceFlag = &cli.BoolFlag{
		Name: "skiptrace",
		Usage: "If 'skiptrace' is set to true, then the evms will execute _without_ tracing, and only the final stateroot will be compared after execution.\n" +
			"This mode is faster, and can be used even if the clients-under-test has known errors in the trace-output, \n" +
			"but has a very high chance of missing cases which could be exploitable.",
	}
	TypeFlag = &cli.StringFlag{
		Name:    "type",
		Aliases: []string{"t"},
		Usage:   "Type of packet to generate (e.g., 'ping')",
	}
	CountFlag = &cli.IntFlag{
		Name:  "count",
		Usage: "Number of tests that should be benched/executed/generated",
	}
	ThreadsFlag = &cli.IntFlag{
		Name:  "threads",
		Usage: "Number of generator threads started (default = NUMCPU)",
		Value: runtime.NumCPU(),
	}
	ChainDirFlag = &cli.StringFlag{
		Name:  "chain",
		Usage: "Test chain directory (required)",
	}
	traceLengthSA = utils.NewSlidingAverage()
)
