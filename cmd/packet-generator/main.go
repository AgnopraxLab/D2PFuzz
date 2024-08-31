package main

import (
	"D2PFuzz/common"
	"D2PFuzz/flags"
	"fmt"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v2"
)

//TODO: packet-generator --protocol "discv4" --type "ping" --count 2 --file "./test.txt"

var (
	app = initApp()
)

func initApp() *cli.App {
	app := cli.NewApp()
	app.Name = filepath.Base(os.Args[0])
	app.Authors = []*cli.Author{{Name: "Kimmich Wu"}}
	app.Usage = "A simple fuzzer with various options"
	app.Flags = append(app.Flags,
		flags.ProtocolFlag,
		flags.TypeFlag,
		flags.CountFlag,
		flags.FileFlag,
		flags.GenTestFlag,
	)
	app.Action = generate
	return app
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate(ctx *cli.Context) error {
	return common.ExecuteGenerator(ctx)
}
