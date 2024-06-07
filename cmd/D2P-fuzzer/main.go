package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/log"
	"github.com/urfave/cli/v2"
)

var (
	engineFlag = &cli.StringSliceFlag{
		Name:  "engine",
		Usage: "fuzzing-engine",
		Value: cli.NewStringSlice(fuzzing.FactoryNames()...),
	}
	forkFlag = &cli.StringFlag{
		Name:  "fork",
		Usage: "What fork to use (London, Merge, Byzantium, Shanghai, etc)",
		Value: "Merge",
	}
	app = initApp()
)

func initApp() *cli.App {
	app := cli.NewApp()
	app.Name = filepath.Base(os.Args[0])
	app.Authors = []*cli.Author{{Name: "Martin Holst Swende"}}
	app.Usage = "Fuzzer with various targets"
	app.Flags = append(app.Flags)
	app.Action = startFuzzer
	return app
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func startFuzzer(ctx *cli.Context) (err error) {
	loglevel := slog.Level(ctx.Int(common.VerbosityFlag.Name))
	log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(os.Stderr, loglevel, true)))
	log.Root().Write(loglevel, "Set loglevel", "level", loglevel)
}
