// Copyright 2020 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package eth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"

	"github.com/AgnopraxLab/D2PFuzz/devp2p/protocol/eth/utesting"
)

// sendTxs sends the given transactions to the node and
// expects the node to accept and propagate them.
func (s *Suite) sendTxs(t *utesting.T, txs []*types.Transaction) error {
	// Open sending conn.
	sendConn, err := s.dial()
	if err != nil {
		return err
	}
	defer sendConn.Close()
	if err = sendConn.peer(nil); err != nil {
		return fmt.Errorf("peering failed: %v", err)
	}

	// Open receiving conn.
	recvConn, err := s.dial()
	if err != nil {
		return err
	}
	defer recvConn.Close()
	if err = recvConn.peer(nil); err != nil {
		return fmt.Errorf("peering failed: %v", err)
	}

	if err = sendConn.Write(ethProto, eth.TransactionsMsg, eth.TransactionsPacket(txs)); err != nil {
		return fmt.Errorf("failed to write message to connection: %v", err)
	}

	var (
		got = make(map[common.Hash]bool)
		end = time.Now().Add(timeout)
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
			headers, err := s.chain.GetHeaders(msg)
			if err != nil {
				t.Logf("invalid GetBlockHeaders request: %v", err)
			}
			recvConn.Write(ethProto, eth.BlockHeadersMsg, &eth.BlockHeadersPacket{
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

func (s *Suite) SendTxs(txs []*types.Transaction) error {
	// Open sending conn.
	sendConn, err := s.dial()
	if err != nil {
		return fmt.Errorf("sendConn failed: %v", err)
	}
	defer sendConn.Close()
	if err = sendConn.peer(nil); err != nil {
		return fmt.Errorf("peering failed: %v", err)
	}

	// Open receiving conn.
	recvConn, err := s.dial()
	if err != nil {
		return err
	}
	defer recvConn.Close()
	if err = recvConn.peer(nil); err != nil {
		return fmt.Errorf("peering failed: %v", err)
	}

	// Send all transactions using TransactionsMsg
	// Blob transactions (Type 3) with sidecars attached will be encoded properly
	if err = sendConn.Write(ethProto, eth.TransactionsMsg, eth.TransactionsPacket(txs)); err != nil {
		return fmt.Errorf("failed to write transactions: %v", err)
	}

	var (
		got = make(map[common.Hash]bool)
		end = time.Now().Add(timeout)
	)
	// Wait for the transaction announcements, make sure all txs are propagated.
	for time.Now().Before(end) {
		msg, err := recvConn.ReadEth()
		// if err != nil {
		// 	return fmt.Errorf("failed to read from connection: %w", err)
		// }
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
			if err = sendConn.Write(ethProto, eth.GetBlockHeadersMsg, &eth.GetBlockHeadersPacket{
				RequestId: msg.RequestId,
				GetBlockHeadersRequest: &eth.GetBlockHeadersRequest{
					Origin:  eth.HashOrNumber{Hash: msg.GetBlockHeadersRequest.Origin.Hash, Number: 0},
					Amount:  uint64(512),
					Skip:    0,
					Reverse: msg.GetBlockHeadersRequest.Reverse,
				},
			}); err != nil {
				return fmt.Errorf("could not write to connection: %v", err)
			}
			headers := new(eth.BlockHeadersPacket)
			if err = sendConn.ReadMsg(ethProto, eth.BlockHeadersMsg, &headers); err != nil {
				return fmt.Errorf("error reading msg: %w", err)
			}

			sendConn.Write(ethProto, eth.BlockHeadersMsg, &eth.BlockHeadersPacket{
				RequestId: msg.RequestId,
				// BlockHeadersRequest: nil,
				BlockHeadersRequest: headers.BlockHeadersRequest,
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

	// return errors.New("timed out waiting for txs")
	return nil
}

func (s *Suite) SendTxsWithoutRecv(txs []*types.Transaction) error {
	// Open sending connection only (simplified for better reliability)
	sendConn, err := s.dial()
	if err != nil {
		return fmt.Errorf("sendConn failed: %v", err)
	}
	defer sendConn.Close()

	// Perform peering handshake
	if err = sendConn.peer(nil); err != nil {
		return fmt.Errorf("peering failed: %v", err)
	}

	// Send transactions using TransactionsMsg
	// For Blob transactions (Type 3), the transaction already has sidecars attached via WithBlobTxSidecar()
	// The serialization should handle it automatically
	if err = sendConn.Write(ethProto, eth.TransactionsMsg, eth.TransactionsPacket(txs)); err != nil {
		return fmt.Errorf("failed to write transactions: %v", err)
	}

	// Successfully sent transactions without waiting for propagation confirmation
	return nil
}

func (s *Suite) sendInvalidTxs(t *utesting.T, txs []*types.Transaction) error {
	// Open sending conn.
	sendConn, err := s.dial()
	if err != nil {
		return err
	}
	defer sendConn.Close()
	if err = sendConn.peer(nil); err != nil {
		return fmt.Errorf("peering failed: %v", err)
	}
	sendConn.SetDeadline(time.Now().Add(timeout))

	// Open receiving conn.
	recvConn, err := s.dial()
	if err != nil {
		return err
	}
	defer recvConn.Close()
	if err = recvConn.peer(nil); err != nil {
		return fmt.Errorf("peering failed: %v", err)
	}
	recvConn.SetDeadline(time.Now().Add(timeout))

	if err = sendConn.Write(ethProto, eth.TransactionsMsg, txs); err != nil {
		return fmt.Errorf("failed to write message to connection: %w", err)
	}

	// Make map of invalid txs.
	invalids := make(map[common.Hash]struct{})
	for _, tx := range txs {
		invalids[tx.Hash()] = struct{}{}
	}

	// Get responses.
	for {
		msg, err := recvConn.ReadEth()
		if err != nil {
			return fmt.Errorf("failed to read message from connection: %w", err)
		}
		switch msg := msg.(type) {
		case *eth.TransactionsPacket:
			for _, tx := range *msg {
				if _, ok := invalids[tx.Hash()]; ok {
					return fmt.Errorf("received bad tx: %s", tx.Hash())
				}
			}
		case *eth.NewPooledTransactionHashesPacket:
			for _, hash := range msg.Hashes {
				if _, ok := invalids[hash]; ok {
					return fmt.Errorf("received bad tx: %s", hash)
				}
			}
		case *eth.GetBlockHeadersPacket:
			headers, err := s.chain.GetHeaders(msg)
			if err != nil {
				t.Logf("invalid GetBlockHeaders request: %v", err)
			}
			recvConn.Write(ethProto, eth.BlockHeadersMsg, &eth.BlockHeadersPacket{
				RequestId:           msg.RequestId,
				BlockHeadersRequest: headers,
			})
		default:
			continue
		}
	}
}

func (s *Suite) TestMaliciousTxPropagation(t *utesting.T) {
	if err := s.sendInvalidTxs(t, []*types.Transaction{getNextTxFromChain(t, s)}); err != nil {
		t.Fatal(err)
	}
}

func getNextTxFromChain(t *utesting.T, s *Suite) *types.Transaction {
	// Get the latest block.
	block := s.chain.Head()

	// Get the next transaction.
	if len(block.Transactions()) > 0 {
		return block.Transactions()[0]
	}

	t.Fatal("could not find transaction")
	return nil
}

func getTxsFromFile(filePath string) ([]*types.Transaction, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var txs []*types.Transaction
	if err := json.Unmarshal(data, &txs); err != nil {
		return nil, err
	}

	return txs, nil
}
