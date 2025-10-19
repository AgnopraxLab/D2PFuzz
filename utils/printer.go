package utils

import (
	"fmt"
	"reflect"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
)

// PrintTransaction prints transaction details
func PrintTransaction(tx *types.Transaction) {
	fmt.Printf("Transaction Details:\n")
	fmt.Printf("  Hash: %s\n", tx.Hash().Hex())
	fmt.Printf("  Nonce: %d\n", tx.Nonce())
	fmt.Printf("  Gas Price: %d\n", tx.GasPrice())
	fmt.Printf("  Gas: %d\n", tx.Gas())
	fmt.Printf("  To: %s\n", tx.To().Hex())
	fmt.Printf("  Value: %s\n", tx.Value())
	fmt.Printf("  Data: %x\n", tx.Data())
	// Signature information
	v, r, s := tx.RawSignatureValues()
	fmt.Printf("Signature V: %d\n", v.Uint64())
	fmt.Printf("Signature R: %s\n", r.String())
	fmt.Printf("Signature S: %s\n", s.String())
}

// PrintPooledTransactions prints pooled transactions response
func PrintPooledTransactions(resp eth.PooledTransactionsResponse) {
	if len(resp) == 0 {
		fmt.Println("No pooled transaction data")
		return
	}

	fmt.Printf("=== Pooled Transactions Response ===\n")
	fmt.Printf("Total transactions: %d\n\n", len(resp))

	for i, tx := range resp {
		fmt.Printf("--- Transaction %d ---\n", i+1)
		fmt.Printf("Transaction hash: %s\n", tx.Hash().Hex())
		fmt.Printf("Nonce: %d\n", tx.Nonce())

		if tx.To() != nil {
			fmt.Printf("To address: %s\n", tx.To().Hex())
		} else {
			fmt.Printf("To address: Contract creation transaction\n")
		}

		fmt.Printf("Transfer amount: %s Wei\n", tx.Value().String())

		// Calculate sender address (if possible)
		if signer := types.LatestSignerForChainID(tx.ChainId()); signer != nil {
			if sender, err := types.Sender(signer, tx); err == nil {
				fmt.Printf("Sender address: %s\n", sender.Hex())
			} else {
				fmt.Printf("Sender address: Unable to calculate (%v)\n", err)
			}
		}

		fmt.Println("=================================")
	}
}

// PrintHeaders prints block headers
func PrintHeaders(headers *eth.BlockHeadersPacket) {
	for i, header := range headers.BlockHeadersRequest {
		fmt.Printf("=== Header %d ===\n", i+1)
		fmt.Printf("Block Number: %d\n", header.Number.Uint64())
		fmt.Printf("Block Hash: %s\n", header.Hash().Hex())
		fmt.Printf("Parent Block Hash: %s\n", header.ParentHash.Hex())
		fmt.Printf("Timestamp: %d\n", header.Time)
		fmt.Printf("Gas Limit: %d\n", header.GasLimit)
		fmt.Printf("Gas Used: %d\n", header.GasUsed)
		fmt.Printf("Difficulty: %s\n", header.Difficulty.String())
		fmt.Printf("Miner Address: %s\n", header.Coinbase.Hex())
		fmt.Printf("State Root: %s\n", header.Root.Hex())
		fmt.Printf("Transaction Root: %s\n", header.TxHash.Hex())
		fmt.Printf("Receipt Root: %s\n", header.ReceiptHash.Hex())
		fmt.Println()
	}
}

// PrintReceipts prints receipts
func PrintReceipts(receipts []*eth.ReceiptList68) {
	if len(receipts) == 0 {
		fmt.Println("No receipt data")
		return
	}

	for i, receiptList := range receipts {
		fmt.Printf("=== Receipt list for block %d ===\n", i+1)

		if receiptList == nil {
			fmt.Println("Receipt list is empty")
			continue
		}

		// Since the specific structure of ReceiptList68 is unclear, we need to access its fields through reflection
		reflectValue := reflect.ValueOf(receiptList).Elem()
		reflectType := reflectValue.Type()

		fmt.Printf("Receipt list type: %s\n", reflectType.Name())
		fmt.Printf("Field count: %d\n", reflectValue.NumField())

		// Iterate through all fields
		for j := 0; j < reflectValue.NumField(); j++ {
			field := reflectType.Field(j)
			fieldValue := reflectValue.Field(j)

			fmt.Printf("  Field %s (%s): ", field.Name, field.Type)

			// If the field can be accessed
			if fieldValue.CanInterface() {
				switch fieldValue.Kind() {
				case reflect.Slice:
					fmt.Printf("Slice length %d\n", fieldValue.Len())
					// If it's a Receipt slice, print detailed information for each Receipt
					if field.Type.String() == "[]*types.Receipt" {
						for k := 0; k < fieldValue.Len(); k++ {
							receipt := fieldValue.Index(k).Interface().(*types.Receipt)
							PrintSingleReceipt(receipt, k+1)
						}
					}
				case reflect.Ptr:
					if !fieldValue.IsNil() {
						fmt.Printf("%v\n", fieldValue.Interface())
					} else {
						fmt.Println("nil")
					}
				default:
					fmt.Printf("%v\n", fieldValue.Interface())
				}
			} else {
				fmt.Println("Cannot access")
			}
		}
		fmt.Println()
	}
}

// PrintSingleReceipt prints a single receipt
func PrintSingleReceipt(receipt *types.Receipt, index int) {
	fmt.Printf("    --- Receipt %d ---\n", index)
	fmt.Printf("    Transaction Type: %d\n", receipt.Type)
	fmt.Printf("    Transaction Hash: %s\n", receipt.TxHash.Hex())
	fmt.Printf("    Status: %d\n", receipt.Status)
	fmt.Printf("    Cumulative Gas Used: %d\n", receipt.CumulativeGasUsed)
	fmt.Printf("    Gas Used: %d\n", receipt.GasUsed)
	
	if receipt.EffectiveGasPrice != nil {
		fmt.Printf("    Effective Gas Price: %s Wei\n", receipt.EffectiveGasPrice.String())
	}

	if receipt.ContractAddress != (common.Address{}) {
		fmt.Printf("    Contract Address: %s\n", receipt.ContractAddress.Hex())
	} else {
		fmt.Printf("    Contract Address: None (not a contract creation transaction)\n")
	}

	if len(receipt.Logs) > 0 {
		fmt.Printf("    Log Count: %d\n", len(receipt.Logs))
	} else {
		fmt.Printf("    Logs: None\n")
	}

	fmt.Println()
}

// PrintTestSummary prints a formatted test summary
func PrintTestSummary(testName string, stats map[string]interface{}) {
	fmt.Printf("\n=== %s Summary ===\n", testName)
	for key, value := range stats {
		fmt.Printf("%s: %v\n", key, value)
	}
	fmt.Println("==============================")
}

// PrintSeparator prints a visual separator
func PrintSeparator() {
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

// PrintProgress prints a progress indicator
func PrintProgress(current, total int, message string) {
	percentage := float64(current) * 100.0 / float64(total)
	fmt.Printf("\r[%3.0f%%] %s (%d/%d)", percentage, message, current, total)
	if current == total {
		fmt.Println() // New line when complete
	}
}

