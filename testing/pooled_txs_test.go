package testing

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"github.com/AgnopraxLab/D2PFuzz/config"
	ethtest "github.com/AgnopraxLab/D2PFuzz/devp2p/protocol/eth"
	"github.com/AgnopraxLab/D2PFuzz/ethclient"
	"github.com/AgnopraxLab/D2PFuzz/transaction"
	"github.com/AgnopraxLab/D2PFuzz/utils"
)

// GetPooledTxsTest tests GetPooledTransactions
type GetPooledTxsTest struct{}

func (t *GetPooledTxsTest) Name() string {
	return "getPooledTxs"
}

func (t *GetPooledTxsTest) Description() string {
	return "Test GetPooledTransactions protocol message"
}

func (t *GetPooledTxsTest) Run(cfg *config.Config) error {
	fmt.Println("=== D2PFuzz GetPooledTxs Testing Tool ===")

	nodeIndex := cfg.Test.GetPooledTxsNodeIndex
	if nodeIndex < 0 || nodeIndex >= cfg.GetNodeCount() {
		return fmt.Errorf("invalid node index: %d, valid range: 0-%d", nodeIndex, cfg.GetNodeCount()-1)
	}

	jwtSecret, err := transaction.ParseJWTSecretFromHexString(cfg.P2P.JWTSecret)
	if err != nil {
		return fmt.Errorf("failed to parse JWT secret: %v", err)
	}

	enodeStr := cfg.P2P.BootstrapNodes[nodeIndex]
	node, err := enode.Parse(enode.ValidSchemes, enodeStr)
	if err != nil {
		return fmt.Errorf("failed to parse enode: %v", err)
	}

	s, err := ethtest.NewSuite(node, node.IP().String()+":8551", common.Bytes2Hex(jwtSecret[:]), cfg.GetNodeName(nodeIndex))
	if err != nil {
		return fmt.Errorf("failed to create suite: %v", err)
	}

	txHashes := []common.Hash{}

	// Read hash values from file
	file, err := os.Open(cfg.Paths.TxHashesExt)
	if err != nil {
		// Try alternative path
		file, err = os.Open(cfg.Paths.TxHashes)
		if err != nil {
			return fmt.Errorf("failed to open tx hashes file: %v", err)
		}
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and lines starting with #
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Convert hex string to common.Hash and add to array
		txHashes = append(txHashes, common.HexToHash(line))
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading tx hashes file: %v", err)
	}

	fmt.Printf("Loaded %d transaction hashes from file\n", len(txHashes))

	// Query transactions
	foundTxs, err := transaction.Query(ethclient.ClientFromSuite(s, cfg, nodeIndex), txHashes)
	if err != nil {
		fmt.Printf("Query failed: %v\n", err)
		return err
	}

	fmt.Printf("Query completed successfully, found %d transactions\n", len(foundTxs))

	// Print found transactions
	utils.PrintPooledTransactions(eth.PooledTransactionsResponse(foundTxs))

	return nil
}
