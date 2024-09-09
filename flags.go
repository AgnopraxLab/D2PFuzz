package main

import (
	"runtime"

	"github.com/urfave/cli/v2"
)

var (
	countFlag = &cli.IntFlag{
		Name:  "count",
		Usage: "Number of tests that should be benched/executed/generated",
	}

	threadsFlag = &cli.IntFlag{
		Name:  "threads",
		Usage: "Number of generator threads started (default = NUMCPU)",
		Value: runtime.NumCPU(),
	}

	protocolFlag = &cli.StringFlag{
		Name:  "protocol",
		Usage: "Specify the protocol to test",
	}

	targetFlag = &cli.StringFlag{
		Name:  "target",
		Usage: "Target flag",
	}

	engineFlag = &cli.StringFlag{
		Name:  "engine",
		Usage: "Engine flag",
	}
)
