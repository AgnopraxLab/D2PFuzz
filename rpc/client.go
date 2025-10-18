package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// RPCClient represents an RPC client for Ethereum node communication
type RPCClient struct {
	URL    string
	Client *http.Client
}

// NewRPCClient creates a new RPC client with the specified URL
func NewRPCClient(rpcURL string) *RPCClient {
	return &RPCClient{
		URL: rpcURL,
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SendRequest sends a JSON-RPC request to the Ethereum node
func (c *RPCClient) SendRequest(method string, params []interface{}) (map[string]interface{}, error) {
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	resp, err := c.Client.Post(c.URL, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	// Check for errors
	if errorData, exists := result["error"]; exists {
		return nil, fmt.Errorf("RPC error: %v", errorData)
	}

	return result, nil
}

// CallContext performs a JSON-RPC call with the given arguments. If the context is
// canceled before the call has successfully returned, CallContext returns immediately.
//
// The result must be a pointer so that package json can unmarshal into it. You
// can also pass nil, in which case the result is ignored.
func (c *RPCClient) CallContext(ctx context.Context, result interface{}, method string, args ...interface{}) error {
	if result != nil && reflect.TypeOf(result).Kind() != reflect.Ptr {
		return fmt.Errorf("call result parameter must be pointer or nil interface: %v", result)
	}

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  args,
		"id":      1,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.URL, strings.NewReader(string(jsonData)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var rpcResponse struct {
		JSONRPC string          `json:"jsonrpc"`
		Result  json.RawMessage `json:"result"`
		Error   *struct {
			Code    int             `json:"code"`
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data"`
		} `json:"error"`
		ID int `json:"id"`
	}

	if err := json.Unmarshal(body, &rpcResponse); err != nil {
		return err
	}

	if rpcResponse.Error != nil {
		return fmt.Errorf("RPC error %d: %s", rpcResponse.Error.Code, rpcResponse.Error.Message)
	}

	if len(rpcResponse.Result) == 0 {
		return fmt.Errorf("no result returned")
	}

	if result == nil {
		return nil
	}

	return json.Unmarshal(rpcResponse.Result, result)
}

// NonceAt returns the account nonce of the given account.
// The block number can be nil, in which case the nonce is taken from the latest known block.
func (c *RPCClient) NonceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (uint64, error) {
	var result hexutil.Uint64
	err := c.CallContext(ctx, &result, "eth_getTransactionCount", account, toBlockNumArg(blockNumber))
	return uint64(result), err
}

// toBlockNumArg converts a big.Int to a block number argument for RPC calls
func toBlockNumArg(blockNumber *big.Int) string {
	if blockNumber == nil {
		return "latest"
	}
	return hexutil.EncodeBig(blockNumber)
}
