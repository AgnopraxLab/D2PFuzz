// This is a tool to check the chain.rlp file
package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

// Structure to store block details
type BlockInfo struct {
	Number       uint64   `json:"number"`
	Hash         string   `json:"hash"`
	ParentHash   string   `json:"parentHash"`
	Time         uint64   `json:"timestamp"`
	GasUsed      uint64   `json:"gasUsed"`
	GasLimit     uint64   `json:"gasLimit"`
	Difficulty   string   `json:"difficulty"`
	TxCount      int      `json:"transactionCount"`
	Size         uint64   `json:"size"`
	Coinbase     string   `json:"miner"`
	ExtraData    string   `json:"extraData"`
	Transactions []TxInfo `json:"transactions,omitempty"`
}

// Structure to store transaction details
type TxInfo struct {
	Hash     string `json:"hash"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Value    string `json:"value"`
	Gas      uint64 `json:"gas"`
	GasPrice string `json:"gasPrice"`
	Nonce    uint64 `json:"nonce"`
	Type     uint8  `json:"type"`
}

func main() {
	// Define command line flags
	var (
		blockNum   = flag.Int64("block", -1, "Specify block number to view (-1 means not specified)")
		showTx     = flag.Bool("tx", false, "Show transaction details")
		jsonOutput = flag.Bool("json", false, "Output in JSON format")
		showRange  = flag.String("range", "", "Show blocks in range (format: start-end)")
	)

	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Println("Usage: ./checker [options] chain.rlp")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		return
	}

	chainfile := flag.Arg(0)

	// Open file
	fh, err := os.Open(chainfile)
	if err != nil {
		fmt.Printf("Cannot open file: %v\n", err)
		return
	}
	defer fh.Close()

	// Set up reader
	var reader io.Reader = fh
	if strings.HasSuffix(chainfile, ".gz") {
		if reader, err = gzip.NewReader(reader); err != nil {
			fmt.Printf("Cannot create gzip reader: %v\n", err)
			return
		}
	}

	// Create RLP stream
	stream := rlp.NewStream(reader, 0)

	// Count blocks
	blockCount := 0
	var totalGas uint64 = 0
	var lastBlockNumber uint64 = 0

	// Parse range parameter
	var rangeStart, rangeEnd int64 = -1, -1
	if *showRange != "" {
		fmt.Sscanf(*showRange, "%d-%d", &rangeStart, &rangeEnd)
	}

	// Read all blocks
	for {
		var b types.Block
		if err := stream.Decode(&b); err == io.EOF {
			break
		} else if err != nil {
			fmt.Printf("Error decoding at block %d: %v\n", blockCount, err)
			return
		}

		blockCount++
		totalGas += b.GasUsed()
		lastBlockNumber = b.NumberU64()

		// Handle single block view request
		if *blockNum == int64(b.NumberU64()) {
			printBlockInfo(&b, *showTx, *jsonOutput)
			if !*jsonOutput {
				fmt.Println("\nContinuing to scan remaining blocks...")
			}
		}

		// Handle block range view request
		if rangeStart != -1 && rangeEnd != -1 {
			if int64(b.NumberU64()) >= rangeStart && int64(b.NumberU64()) <= rangeEnd {
				printBlockInfo(&b, *showTx, *jsonOutput)
			}
		}

		// Print progress every 1000 blocks
		if blockCount%1000 == 0 {
			fmt.Printf("Processed %d blocks...\n", blockCount)
		}
	}

	if !*jsonOutput {
		fmt.Printf("\nFile analysis complete:\n")
		fmt.Printf("Total blocks: %d\n", blockCount)
		fmt.Printf("Last block number: %d\n", lastBlockNumber)
		fmt.Printf("Total gas used: %d\n", totalGas)

		if blockCount == 0 {
			fmt.Println("Warning: No block data in file!")
		}
	}
}

func printBlockInfo(block *types.Block, showTx bool, jsonOutput bool) {
	info := BlockInfo{
		Number:     block.NumberU64(),
		Hash:       block.Hash().String(),
		ParentHash: block.ParentHash().String(),
		Time:       block.Time(),
		GasUsed:    block.GasUsed(),
		GasLimit:   block.GasLimit(),
		Difficulty: block.Difficulty().String(),
		TxCount:    len(block.Transactions()),
		Size:       block.Size(),
		Coinbase:   block.Coinbase().String(),
		ExtraData:  string(block.Extra()),
	}

	if showTx {
		info.Transactions = make([]TxInfo, len(block.Transactions()))
		for i, tx := range block.Transactions() {
			txInfo := TxInfo{
				Hash:     tx.Hash().String(),
				Gas:      tx.Gas(),
				GasPrice: tx.GasPrice().String(),
				Nonce:    tx.Nonce(),
				Value:    tx.Value().String(),
				Type:     tx.Type(),
			}
			if tx.To() != nil {
				txInfo.To = tx.To().String()
			}
			info.Transactions[i] = txInfo
		}
	}

	if jsonOutput {
		jsonData, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			fmt.Printf("JSON encoding error: %v\n", err)
			return
		}
		fmt.Println(string(jsonData))
	} else {
		fmt.Printf("\nBlock #%d Information:\n", info.Number)
		fmt.Printf("Hash: %s\n", info.Hash)
		fmt.Printf("Parent Hash: %s\n", info.ParentHash)
		fmt.Printf("Timestamp: %d\n", info.Time)
		fmt.Printf("Gas Used: %d\n", info.GasUsed)
		fmt.Printf("Gas Limit: %d\n", info.GasLimit)
		fmt.Printf("Difficulty: %s\n", info.Difficulty)
		fmt.Printf("Transaction Count: %d\n", info.TxCount)
		fmt.Printf("Block Size: %d bytes\n", info.Size)
		fmt.Printf("Miner Address: %s\n", info.Coinbase)
		fmt.Printf("Extra Data: %s\n", info.ExtraData)

		if showTx && len(info.Transactions) > 0 {
			fmt.Printf("\nTransaction Details:\n")
			for i, tx := range info.Transactions {
				fmt.Printf("\n  Transaction #%d:\n", i)
				fmt.Printf("    Hash: %s\n", tx.Hash)
				fmt.Printf("    To: %s\n", tx.To)
				fmt.Printf("    Value: %s\n", tx.Value)
				fmt.Printf("    Gas: %d\n", tx.Gas)
				fmt.Printf("    Gas Price: %s\n", tx.GasPrice)
				fmt.Printf("    Nonce: %d\n", tx.Nonce)
				fmt.Printf("    Type: %d\n", tx.Type)
			}
		}
	}
}
