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

// Package main creates a fuzzer for Ethereum DevP2P Protocol implementations.
package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"

	"github.com/AgnopraxLab/D2PFuzz/benchmark"
	"github.com/AgnopraxLab/D2PFuzz/fuzzer"
	"github.com/AgnopraxLab/D2PFuzz/generator"
)

var benchCommand = &cli.Command{
	Name:   "bench",
	Usage:  "Starts a benchmarking run",
	Action: bench,
	Flags: []cli.Flag{
		countFlag,
		protocolFlag,
		targetFlag,
		engineFlag,
		chainEnvDirFlag,
		packetTypeFlag,
	},
}

var runCommand = &cli.Command{
	Name:   "run",
	Usage:  "Runs the fuzzer",
	Action: run,
	Flags: []cli.Flag{
		threadsFlag,
		protocolFlag,
		targetFlag,
		engineFlag,
		chainEnvDirFlag,
	},
}

var genCommand = &cli.Command{
	Name:   "generator",
	Usage:  "Runs the generator",
	Action: generate,
	Flags: []cli.Flag{
		protocolFlag,
		targetFlag,
		chainEnvDirFlag,
		packetTypeFlag,
	},
}

func initApp() *cli.App {
	app := cli.NewApp()
	app.Name = "D2PFuzz"
	app.Usage = "Generator for Ethereum DevP2P protocol tests"
	app.Commands = []*cli.Command{
		benchCommand,
		runCommand,
		genCommand,
	}
	return app
}

var app = initApp()

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func bench(c *cli.Context) error {
	protocol := c.String("protocol")
	target := c.String("target")
	chainDir := c.String("chain")
	packetType := c.String("ptype")
	count := c.Int("count")
	engine := c.Int("engine")

	benchmark.RunFullBench(protocol, target, chainDir, packetType, count, engine)
	return nil
}

func run(c *cli.Context) error {
	protocol := c.String("protocol")
	target := c.String("target")
	chainDir := c.String("chain")
	engine := c.Int("engine")
	threads := c.Int("threads")

	return fuzzer.RunFuzzer(protocol, target, chainDir, engine, threads)
}

func generate(c *cli.Context) error {
	// Retrieve the protocol and packet type from CLI flags
	protocol := c.String("protocol")
	packetType := c.String("ptype")
	target := c.String("target")
	chainDir := c.String("chain")

	return generator.RunGenerate(protocol, target, chainDir, packetType)
}
