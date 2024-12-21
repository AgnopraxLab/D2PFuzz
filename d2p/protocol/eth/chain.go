package eth

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/forkid"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	neth "github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/catalyst"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

type Chain struct {
	genesis core.Genesis
	blocks  []*types.Block
	state   map[common.Address]state.DumpAccount // state of head block
	senders map[common.Address]*senderInfo
	config  *params.ChainConfig
}

type senderInfo struct {
	Key   *ecdsa.PrivateKey `json:"key"`
	Nonce uint64            `json:"nonce"`
}

type Addresses []common.Address

func (a Addresses) Len() int {
	return len(a)
}

func (a Addresses) Less(i, j int) bool {
	return bytes.Compare(a[i][:], a[j][:]) < 0
}

func (a Addresses) Swap(i, j int) {
	tmp := a[i]
	a[i] = a[j]
	a[j] = tmp
}

func NewChain(dir string) (*Chain, error) {
	gen, err := loadGenesis(filepath.Join(dir, "genesis.json"))
	if err != nil {
		return nil, err
	}
	gblock := gen.ToBlock()

	blocks, err := blocksFromFile(filepath.Join(dir, "chain.rlp"), gblock)
	if err != nil {
		return nil, err
	}
	sTate, err := readState(filepath.Join(dir, "headstate.json"))
	if err != nil {
		return nil, err
	}
	accounts, err := readAccounts(filepath.Join(dir, "accounts.json"))
	if err != nil {
		return nil, err
	}
	return &Chain{
		genesis: gen,
		blocks:  blocks,
		state:   sTate,
		senders: accounts,
		config:  gen.Config,
	}, nil
}

func loadGenesis(genesisFile string) (core.Genesis, error) {
	chainConfig, err := os.ReadFile(genesisFile)
	if err != nil {
		return core.Genesis{}, err
	}
	var gen core.Genesis
	if err := json.Unmarshal(chainConfig, &gen); err != nil {
		return core.Genesis{}, err
	}
	return gen, nil
}

func blocksFromFile(chainfile string, gblock *types.Block) ([]*types.Block, error) {
	// Load chain.rlp.
	fh, err := os.Open(chainfile)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	var reader io.Reader = fh
	if strings.HasSuffix(chainfile, ".gz") {
		if reader, err = gzip.NewReader(reader); err != nil {
			return nil, err
		}
	}
	stream := rlp.NewStream(reader, 0)
	var blocks = make([]*types.Block, 1)
	blocks[0] = gblock
	for i := 0; ; i++ {
		var b types.Block
		if err := stream.Decode(&b); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("at block index %d: %v", i, err)
		}
		if b.NumberU64() != uint64(i+1) {
			return nil, fmt.Errorf("block at index %d has wrong number %d", i, b.NumberU64())
		}
		blocks = append(blocks, &b)
	}
	return blocks, nil
}

func readState(file string) (map[common.Address]state.DumpAccount, error) {
	f, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("unable to read state: %v", err)
	}
	var dump state.Dump
	if err := json.Unmarshal(f, &dump); err != nil {
		return nil, fmt.Errorf("unable to unmarshal state: %v", err)
	}

	sTate := make(map[common.Address]state.DumpAccount)
	for key, acct := range dump.Accounts {
		var addr common.Address
		if err := addr.UnmarshalText([]byte(key)); err != nil {
			return nil, fmt.Errorf("invalid address %q", key)
		}
		sTate[addr] = acct
	}
	return sTate, nil
}

func readAccounts(file string) (map[common.Address]*senderInfo, error) {
	f, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("unable to read state: %v", err)
	}
	type account struct {
		Key hexutil.Bytes `json:"key"`
	}
	keys := make(map[common.Address]account)
	if err := json.Unmarshal(f, &keys); err != nil {
		return nil, fmt.Errorf("unable to unmarshal accounts: %v", err)
	}
	accounts := make(map[common.Address]*senderInfo)
	for addr, acc := range keys {
		pk, err := crypto.HexToECDSA(common.Bytes2Hex(acc.Key))
		if err != nil {
			return nil, fmt.Errorf("unable to read private key for %s: %v", err, addr)
		}
		accounts[addr] = &senderInfo{Key: pk, Nonce: 0}
	}
	return accounts, nil
}

// Len returns the length of the chain.
func (c *Chain) Len() int {
	return len(c.blocks)
}

func (c *Chain) Head() *types.Block {
	return c.blocks[c.Len()-1]
}

// TD calculates the total difficulty of the chain at the
// chain head.
func (c *Chain) TD() *big.Int {
	sum := new(big.Int)
	for _, block := range c.blocks[:c.Len()] {
		sum.Add(sum, block.Difficulty())
	}
	return sum
}

func (c *Chain) GetBlock(number int) *types.Block {
	return c.blocks[number]
}

// ForkID gets the fork id of the chain.
func (c *Chain) ForkID() forkid.ID {
	return forkid.NewID(c.config, c.blocks[0], uint64(c.Len()), c.blocks[c.Len()-1].Time())
}

// GetSender returns the address associated with account at the index in the
// pre-funded accounts list.
func (c *Chain) GetSender(idx int) (common.Address, uint64) {
	var accounts Addresses
	for addr := range c.senders {
		accounts = append(accounts, addr)
	}
	sort.Sort(accounts)
	addr := accounts[idx]
	return addr, c.senders[addr].Nonce
}

// SignTx signs a transaction for the specified from account, so long as that
// account was in the hivechain accounts dump.
func (c *Chain) SignTx(from common.Address, tx *types.Transaction) (*types.Transaction, error) {
	signer := types.LatestSigner(c.config)
	acc, ok := c.senders[from]
	if !ok {
		return nil, fmt.Errorf("account not available for signing: %s", from)
	}
	return types.SignTx(tx, signer, acc.Key)
}

// GetHeaders returns the headers base on an ethGetPacketHeadersPacket.
func (c *Chain) GetHeaders(req *GetBlockHeadersPacket) ([]*types.Header, error) {
	if req.Amount < 1 {
		return nil, errors.New("no block headers requested")
	}
	var (
		headers     = make([]*types.Header, req.Amount)
		blockNumber uint64
	)
	// Range over blocks to check if our chain has the requested header.
	for _, block := range c.blocks {
		if block.Hash() == req.Origin.Hash || block.Number().Uint64() == req.Origin.Number {
			headers[0] = block.Header()
			blockNumber = block.Number().Uint64()
		}
	}
	if headers[0] == nil {
		return nil, fmt.Errorf("no headers found for given origin number %v, hash %v", req.Origin.Number, req.Origin.Hash)
	}
	if req.Reverse {
		for i := 1; i < int(req.Amount); i++ {
			blockNumber -= 1 - req.Skip
			headers[i] = c.blocks[blockNumber].Header()
		}
		return headers, nil
	}
	for i := 1; i < int(req.Amount); i++ {
		blockNumber += 1 + req.Skip
		headers[i] = c.blocks[blockNumber].Header()
	}
	return headers, nil
}

func MakeJWTSecret() (string, [32]byte, error) {
	var secret [32]byte
	if _, err := crand.Read(secret[:]); err != nil {
		return "", secret, fmt.Errorf("failed to create jwt secret: %v", err)
	}
	jwtPath := path.Join(os.TempDir(), "jwt_secret")
	if err := os.WriteFile(jwtPath, []byte(hexutil.Encode(secret[:])), 0600); err != nil {
		return "", secret, fmt.Errorf("failed to prepare jwt secret file: %v", err)
	}
	return jwtPath, secret, nil
}

// runGeth creates and starts a geth node
func RunGeth(dir string, jwtPath string) (*node.Node, error) {
	stack, err := node.New(&node.Config{
		AuthAddr: "127.0.0.1",
		AuthPort: 0,
		P2P: p2p.Config{
			ListenAddr:  "127.0.0.1:0",
			NoDiscovery: true,
			MaxPeers:    10, // in case a test requires multiple connections, can be changed in the future
			NoDial:      true,
		},
		JWTSecret: jwtPath,
	})
	if err != nil {
		return nil, err
	}

	err = setupGeth(stack, dir)
	if err != nil {
		stack.Close()
		return nil, err
	}
	if err = stack.Start(); err != nil {
		stack.Close()
		return nil, err
	}
	return stack, nil
}

func setupGeth(stack *node.Node, dir string) error {
	chain, err := NewChain(dir)
	if err != nil {
		return err
	}
	backend, err := neth.New(stack, &ethconfig.Config{
		Genesis:        &chain.genesis,
		NetworkId:      chain.genesis.Config.ChainID.Uint64(), // 19763
		DatabaseCache:  10,
		TrieCleanCache: 10,
		TrieDirtyCache: 16,
		TrieTimeout:    60 * time.Minute,
		SnapshotCache:  10,
	})
	if err != nil {
		return err
	}
	if err := catalyst.Register(stack, backend); err != nil {
		return fmt.Errorf("failed to register catalyst service: %v", err)
	}
	_, err = backend.BlockChain().InsertChain(chain.blocks[1:])
	return err
}

// IncNonce increases the specified signing account's pending nonce.
func (c *Chain) IncNonce(addr common.Address, amt uint64) {
	if _, ok := c.senders[addr]; !ok {
		panic("nonce increment for non-signer")
	}
	c.senders[addr].Nonce += amt
}

// Config returns the chain configuration
func (c *Chain) Config() *params.ChainConfig {
	return c.config
}
