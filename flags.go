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

	engineFlag = &cli.BoolFlag{
		Name:  "engine",
		Usage: "Engine flag",
		Value: false,
	}

	// chainEnvDirFlag eth protocol
	chainEnvDirFlag = &cli.StringFlag{
		Name:  "chain",
		Usage: "Test chain env directory (required)",
	}

	// run generate packet
	packetTypeFlag = &cli.StringFlag{
		Name:  "ptype",
		Usage: "Packet type use generate",
		Value: "random",
	}
)
