package fuzzing

import "github.com/ethereum/go-ethereum/common"

type CliMaker struct {
	forks []string
	root  common.Hash
	logs  common.Hash
}
