// Copyright 2020 Fudong and Hosen
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
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/urfave/cli/v2"

	"D2PFuzz/config"
	"D2PFuzz/flags"
	"D2PFuzz/fuzzer"
)

var setenvCommand = &cli.Command{
	Name:   "setenv",
	Usage:  "Setting up the Fuzz runtime environment",
	Action: setenv,
	Flags: []cli.Flag{
		protocolFlag,
		targetFlag,
		engineFlag,
		chainEnvDirFlag,
	},
}

var runCommand = &cli.Command{
	Name:   "run",
	Usage:  "Runs the fuzzer",
	Action: run,
	Flags: []cli.Flag{
		threadsFlag,
	},
}

const (
	outputRootDir = "out"
	crashesDir    = "crashes"
)

func initApp() *cli.App {
	app := cli.NewApp()
	app.Name = "D2PFuzz"
	app.Usage = "Generator for Ethereum DevP2P protocol tests"
	app.Commands = []*cli.Command{
		setenvCommand,
		runCommand,
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

func run(c *cli.Context) error {
	directories := []string{
		outputRootDir,
		crashesDir,
	}
	for i := 0; i < 256; i++ {
		directories = append(directories, fmt.Sprintf("%v/%v", outputRootDir, common.Bytes2Hex([]byte{byte(i)})))
	}
	ensureDirs(directories...)
	genThreads := c.Int(flags.ThreadsFlag.Name)
	cmd := startGenerator(genThreads)
	return cmd.Wait()
}

func startGenerator(genThreads int) *exec.Cmd {
	var (
		cmdName = "go"
		target  = "FuzzD2P"
		dir     = "./fuzzer/..."
	)
	cmd := exec.Command(cmdName, "test", "--fuzz", target, "--parallel", fmt.Sprint(genThreads), dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Set the output directory
	path, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	directory := filepath.Join(path, outputRootDir)
	env := append(os.Environ(), fmt.Sprintf("%v=%v", fuzzer.EnvKey, directory))
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		panic(err)
	}
	return cmd
}

func ensureDirs(dirs ...string) {
	for _, dir := range dirs {
		_, err := os.Stat(dir)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("Creating directory: %v\n", dir)
				if err = os.Mkdir(dir, 0777); err != nil {
					fmt.Printf("Error while making the dir %q: %v\n", dir, err)
					return
				}
			} else {
				fmt.Printf("Error while using os.Stat dir %q: %v\n", dir, err)
			}
		}
	}
}

func setenv(c *cli.Context) error {
	conf := &config.Config{
		ProtocolFlag: c.String("protocol"),
		TargetFlag:   c.String("target"),
		EngineFlag:   c.Bool("engine"),
		ChainEnvFlag: c.String("chain"),
	}

	err := config.WriteConfig(conf)
	if err != nil {
		return fmt.Errorf("could not write config: %v", err)
	}

	fmt.Println("Config has been set.")
	return nil
}
