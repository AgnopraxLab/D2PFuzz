package main

import (
	"D2PFuzz/common"
	"D2PFuzz/flags"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/log"
	"github.com/urfave/cli/v2"
)

var (
	engineFlag = &cli.StringFlag{
		Name:    "engine",
		Aliases: []string{"p"},
		Usage:   "fuzzing-engine",
		Value:   "randTest",
	}
	app = initApp()
)

func initApp() *cli.App {
	app := cli.NewApp()
	app.Name = filepath.Base(os.Args[0])
	app.Authors = []*cli.Author{{Name: "Kimmich Wu"}}
	app.Usage = "A simple fuzzer with various options"
	app.Flags = append(app.Flags,
		engineFlag,
		flags.VerbosityFlag,
		flags.SkipTraceFlag,
		flags.ThreadFlag,
		flags.LocationFlag,
		flags.FileFlag,
		flags.ProtocolFlag,
		flags.SeedFlag,
	)
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
	loglevel := slog.Level(ctx.Int(flags.VerbosityFlag.Name))
	log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(os.Stderr, loglevel, true)))
	log.Root().Write(loglevel, "Set loglevel", "level", loglevel)

	return common.GenerateAndExecute(ctx)
}
