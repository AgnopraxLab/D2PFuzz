package transaction

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"

	ethtest "github.com/AgnopraxLab/D2PFuzz/devp2p/protocol/eth"
	"github.com/AgnopraxLab/D2PFuzz/ethclient"
)

var (
	pretty = spew.ConfigState{
		Indent:                  "  ",
		DisableCapacities:       true,
		DisablePointerAddresses: true,
		SortKeys:                true,
	}
	timeout = 2 * time.Second
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
		Verify:      false,
		Timeout:     2 * time.Second,
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

// SendBlob sends a blob transaction to the client
// Note: Blob transactions require special handling as they include sidecars
func SendBlob(client *ethclient.Client, blobTx types.Transactions, opts SendOptions) (common.Hash, error) {
	if blobTx == nil {
		return common.Hash{}, fmt.Errorf("blob transaction is nil")
	}

	// Validate blob transaction
	// if err := blob.ValidateBlobTransaction(blobTx); err != nil {
	// 	return common.Hash{}, fmt.Errorf("blob transaction validation failed: %w", err)
	// }

	// Debug: Check if transaction has sidecar
	if blobTx[0].BlobTxSidecar() == nil {
		fmt.Printf("⚠️  WARNING: Blob transaction has NO sidecar attached!\n")
	} else {
		sidecar := blobTx[0].BlobTxSidecar()
		fmt.Printf("🔍 DEBUG: Blob transaction has sidecar with %d blob(s)\n", len(sidecar.Blobs))
	}

	// TODO: check if this is correct
	txHash := blobTx[0].Hash()
	suite := client.GetSuite()

	// For blob transactions, we need to send the transaction with blobs attached
	// The go-ethereum library handles the sidecar encoding automatically
	var err error
	if opts.WaitForRecv || strings.Contains(client.GetNodeName(), "reth") {
		err = suite.SendTxs(blobTx)
	} else {
		err = suite.SendTxsWithoutRecv(blobTx)
	}

	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to send blob transaction: %w", err)
	}

	// Verify if requested
	if opts.Verify {
		if err := Verify(client, []common.Hash{txHash}, opts.Timeout); err != nil {
			return txHash, fmt.Errorf("blob transaction sent but verification failed: %w", err)
		}
	}

	return txHash, nil
}

// SendBlobBatch sends multiple blob transactions in batch
func SendBlobBatch(client *ethclient.Client, blobTxs types.Transactions, opts SendOptions) ([]common.Hash, error) {
	if len(blobTxs) == 0 {
		return nil, nil
	}

	// Validate all blob transactions
	// for i, blobTx := range blobTxs {
	// 	if err := blob.ValidateBlobTransaction(blobTx); err != nil {
	// 		return nil, fmt.Errorf("blob transaction %d validation failed: %w", i, err)
	// 	}
	// }

	// Extract regular transactions
	txs := make([]*types.Transaction, len(blobTxs))
	hashes := make([]common.Hash, len(blobTxs))
	for i, blobTx := range blobTxs {
		txs[i] = blobTx
		hashes[i] = blobTx.Hash()
	}

	// Send using batch method
	suite := client.GetSuite()
	var err error
	if opts.WaitForRecv || client.GetNodeName() == "reth" {
		err = suite.SendTxs(txs)
	} else {
		err = suite.SendTxsWithoutRecv(txs)
	}

	if err != nil {
		return hashes, fmt.Errorf("failed to send blob transactions batch: %w", err)
	}

	// Verify if requested
	if opts.Verify {
		if err := Verify(client, hashes, opts.Timeout); err != nil {
			return hashes, fmt.Errorf("blob transactions sent but verification failed: %w", err)
		}
	}

	return hashes, nil
}

// SendBlobWithoutVerify sends a blob transaction without verification (faster)
func SendBlobWithoutVerify(client *ethclient.Client, blobTx types.Transactions) (common.Hash, error) {
	opts := DefaultSendOptions()
	opts.Verify = false
	return SendBlob(client, blobTx, opts)
}

// VerifyBlob specifically verifies blob transactions
// This is similar to Verify but with additional blob-specific checks
func VerifyBlob(client *ethclient.Client, txHash common.Hash, timeout time.Duration) error {
	// Use the standard verification method
	// Blob transactions appear in the pool like regular transactions
	return Verify(client, []common.Hash{txHash}, timeout)
}

// QueryBlob queries a blob transaction by hash
// Note: This returns the transaction itself, not the blob data
// The blob data is only available through Beacon API
func QueryBlob(client *ethclient.Client, txHash common.Hash) (*types.Transaction, error) {
	txs, err := Query(client, []common.Hash{txHash})
	if err != nil {
		return nil, err
	}

	if len(txs) == 0 {
		return nil, fmt.Errorf("blob transaction not found")
	}

	tx := txs[0]
	if tx.Type() != types.BlobTxType {
		return nil, fmt.Errorf("transaction is not a blob transaction (type: %d)", tx.Type())
	}

	return tx, nil
}

func SendTxs(s *ethtest.Suite, txs []*types.Transaction) error {
	// Open sending conn.
	sendConn, err := s.Dial()
	if err != nil {
		return err
	}
	defer sendConn.Close()
	if err = sendConn.Peer(nil); err != nil {
		return fmt.Errorf("peering failed: %v", err)
	}

	// Open receiving conn.
	recvConn, err := s.Dial()
	if err != nil {
		return err
	}
	defer recvConn.Close()
	if err = recvConn.Peer(nil); err != nil {
		return fmt.Errorf("peering failed: %v", err)
	}

	if err = sendConn.Write(1, eth.TransactionsMsg, eth.TransactionsPacket(txs)); err != nil {
		return fmt.Errorf("failed to write message to connection: %v", err)
	}

	var (
		got = make(map[common.Hash]bool)
		end = time.Now().Add(2 * time.Second)
	)

	// Wait for the transaction announcements, make sure all txs ar propagated.
	for time.Now().Before(end) {
		msg, err := recvConn.ReadEth()
		if err != nil {
			return fmt.Errorf("failed to read from connection: %w", err)
		}
		switch msg := msg.(type) {
		case *eth.TransactionsPacket:
			for _, tx := range *msg {
				got[tx.Hash()] = true
			}
		case *eth.NewPooledTransactionHashesPacket:
			for _, hash := range msg.Hashes {
				got[hash] = true
			}
		case *eth.GetBlockHeadersPacket:
			headers, err := s.GetChain().GetHeaders(msg)
			if err != nil {
				fmt.Errorf("invalid GetBlockHeaders request: %v", err)
			}
			recvConn.Write(1, eth.BlockHeadersMsg, &eth.BlockHeadersPacket{
				RequestId:           msg.RequestId,
				BlockHeadersRequest: headers,
			})
		default:
			return fmt.Errorf("unexpected eth wire msg: %s", pretty.Sdump(msg))
		}
		// Check if all txs received.
		allReceived := func() bool {
			for _, tx := range txs {
				if !got[tx.Hash()] {
					return false
				}
			}
			return true
		}
		if allReceived() {
			return nil
		}
	}
	return errors.New("timed out waiting for txs")
}

func SendTxsWithoutRecv(s *ethtest.Suite, txs []*types.Transaction) error {
	// Open sending conn.
	sendConn, err := s.Dial()
	if err != nil {
		return err
	}
	defer sendConn.Close()
	if err = sendConn.Peer(nil); err != nil {
		return fmt.Errorf("peering failed: %v", err)
	}

	// Open receiving conn.
	recvConn, err := s.Dial()
	if err != nil {
		return err
	}
	defer recvConn.Close()
	if err = recvConn.Peer(nil); err != nil {
		return fmt.Errorf("peering failed: %v", err)
	}

	if err = sendConn.Write(1, eth.TransactionsMsg, eth.TransactionsPacket(txs)); err != nil {
		return fmt.Errorf("failed to write message to connection: %v", err)
	}

	return nil
}
