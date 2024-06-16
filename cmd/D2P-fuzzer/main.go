package main

import (
	"D2PFuzz/common"
	"D2PFuzz/fuzzing"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/log"
	"github.com/urfave/cli/v2"
)

var (
	fileFlag = &cli.StringFlag{
		Name:     "file",
		Aliases:  []string{"f"},
		Usage:    "Specify the file containing test data",
		Required: true,
	}
	forkFlag = &cli.IntFlag{
		Name:    "count",
		Aliases: []string{"c"},
		Usage:   "Specify the number of fuzz processes to start",
		Value:   1,
	}
	protocolFlag = &cli.StringFlag{
		Name:    "protocol",
		Aliases: []string{"p"},
		Usage:   "Specify the protocol to test",
		Value:   "discv4",
	}
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
		fileFlag,
		forkFlag,
		protocolFlag,
		engineFlag,
		common.VerbosityFlag,
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
	loglevel := slog.Level(ctx.Int(common.VerbosityFlag.Name))
	log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(os.Stderr, loglevel, true)))
	log.Root().Write(loglevel, "Set loglevel", "level", loglevel)

	var (
		fName    = ctx.String(fileFlag.Name)
		fork     = ctx.Int(forkFlag.Name)
		protocol = ctx.String(protocolFlag.Name)
		engine   = ctx.String(engineFlag.Name)
	)
	var factory common.GeneratorFn
	if fork == 1 {
		factory = fuzzing.Factory(fName, protocol, engine)
		if factory == nil {
			return fmt.Errorf("unknown target %v", fName)
		}
	} else {
		var factories []common.GeneratorFn
		for i := 0; i < fork; i++ {
			if f := fuzzing.Factory(fName, protocol); f == nil {
				return fmt.Errorf("unknown target %v", fName)
			} else {
				factories = append(factories, f)
			}
			log.Info("Added factory", "name", fName)
		}
		var index atomic.Uint64
		factory = func() *fuzzing.CliMaker {
			i := int(index.Add(1))
			i %= len(factories)
			fn := factories[i]
			return fn()
		}
	}
	return common.GenerateAndExecute(ctx, factory)
}
