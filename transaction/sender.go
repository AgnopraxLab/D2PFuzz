package transaction

import (
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"

	"D2PFuzz/ethclient"
)

// SendOptions holds options for sending transactions
type SendOptions struct {
	Verify      bool          // Whether to verify the transaction was received
	Timeout     time.Duration // Timeout for verification
	WaitForRecv bool          // Whether to wait for recv (needed for some clients like reth)
}

// DefaultSendOptions returns default send options
func DefaultSendOptions() SendOptions {
	return SendOptions{
		Verify:      true,
		Timeout:     12 * time.Second,
		WaitForRecv: false,
	}
}

// Send sends a transaction to the client
// This is the UNIFIED send function that replaces all sendTransaction* variants
func Send(client *ethclient.Client, tx *types.Transaction, opts SendOptions) (common.Hash, error) {
	txHash := tx.Hash()
	suite := client.GetSuite()

	// Determine if we need to wait for recv based on client type
	needsRecv := opts.WaitForRecv || client.GetNodeName() == "reth"

	var err error
	if needsRecv {
		// Some clients (like reth) must handle recv content
		err = suite.SendTxs([]*types.Transaction{tx})
	} else {
		// Other clients can skip recv content handling
		err = suite.SendTxsWithoutRecv([]*types.Transaction{tx})
	}

	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to send transaction: %w", err)
	}

	// Verify if requested
	if opts.Verify {
		if err := Verify(client, []common.Hash{txHash}, opts.Timeout); err != nil {
			return txHash, fmt.Errorf("transaction sent but verification failed: %w", err)
		}
	}

	return txHash, nil
}

// SendBatch sends multiple transactions in batch
func SendBatch(client *ethclient.Client, txs []*types.Transaction, opts SendOptions) ([]common.Hash, error) {
	if len(txs) == 0 {
		return nil, nil
	}

	suite := client.GetSuite()
	hashes := make([]common.Hash, len(txs))
	for i, tx := range txs {
		hashes[i] = tx.Hash()
	}

	// Determine if we need to wait for recv based on client type
	needsRecv := opts.WaitForRecv || client.GetNodeName() == "reth"

	var err error
	if needsRecv {
		err = suite.SendTxs(txs)
	} else {
		err = suite.SendTxsWithoutRecv(txs)
	}

	if err != nil {
		return hashes, fmt.Errorf("failed to send batch transactions: %w", err)
	}

	// Verify if requested
	if opts.Verify {
		if err := Verify(client, hashes, opts.Timeout); err != nil {
			return hashes, fmt.Errorf("transactions sent but verification failed: %w", err)
		}
	}

	return hashes, nil
}

// SendWithoutVerify sends a transaction without verification (faster)
func SendWithoutVerify(client *ethclient.Client, tx *types.Transaction) (common.Hash, error) {
	opts := DefaultSendOptions()
	opts.Verify = false
	return Send(client, tx, opts)
}

// Verify verifies that transactions were received by the node
func Verify(client *ethclient.Client, txHashes []common.Hash, timeout time.Duration) error {
	conn, err := client.Dial()
	if err != nil {
		return fmt.Errorf("failed to dial for verification: %w", err)
	}
	defer conn.Close()

	if err := conn.Peer(nil); err != nil {
		return fmt.Errorf("peering failed: %w", err)
	}

	// Create GetPooledTransactions request
	req := &eth.GetPooledTransactionsPacket{
		RequestId:                    1234,
		GetPooledTransactionsRequest: txHashes,
	}

	if err := conn.Write(1, eth.GetPooledTransactionsMsg, req); err != nil {
		return fmt.Errorf("failed to write verification request: %w", err)
	}

	// Set read timeout
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Read response
	resp := new(eth.PooledTransactionsPacket)
	if err := conn.ReadMsg(1, eth.PooledTransactionsMsg, resp); err != nil {
		return fmt.Errorf("failed to read verification response: %w", err)
	}

	// Verify request ID
	if got, want := resp.RequestId, req.RequestId; got != want {
		return fmt.Errorf("unexpected request id: got %d, want %d", got, want)
	}

	// Check if we got the transactions back
	receivedCount := len(resp.PooledTransactionsResponse)
	expectedCount := len(txHashes)

	if receivedCount == 0 {
		return fmt.Errorf("no transactions found in pool")
	}

	if receivedCount < expectedCount {
		return fmt.Errorf("partial verification: received %d/%d transactions", receivedCount, expectedCount)
	}

	return nil
}

// Query queries transactions by their hashes
func Query(client *ethclient.Client, txHashes []common.Hash) ([]*types.Transaction, error) {
	conn, err := client.Dial()
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}
	defer conn.Close()

	if err = conn.Peer(nil); err != nil {
		return nil, fmt.Errorf("peering failed: %w", err)
	}

	// Create transaction query request
	req := &eth.GetPooledTransactionsPacket{
		RequestId:                    999,
		GetPooledTransactionsRequest: txHashes,
	}

	if err = conn.Write(1, eth.GetPooledTransactionsMsg, req); err != nil {
		return nil, fmt.Errorf("failed to write transaction query: %w", err)
	}

	// Wait for response
	err = conn.SetReadDeadline(time.Now().Add(12 * time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	resp := new(eth.PooledTransactionsPacket)
	if err := conn.ReadMsg(1, eth.PooledTransactionsMsg, resp); err != nil {
		return nil, fmt.Errorf("failed to read transaction response: %w", err)
	}

	// Verify response
	if got, want := resp.RequestId, req.RequestId; got != want {
		return nil, fmt.Errorf("unexpected request id in response: got %d, want %d", got, want)
	}

	successCount := len(resp.PooledTransactionsResponse)
	if successCount == 0 {
		return nil, fmt.Errorf("no transactions found for the requested %d hashes", len(txHashes))
	}

	return resp.PooledTransactionsResponse, nil
}

