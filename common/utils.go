package common

import (
	"D2PFuzz/d2p"
	"D2PFuzz/d2p/protocol/discv4"
	"D2PFuzz/d2p/protocol/discv5"
	"D2PFuzz/d2p/protocol/rlpx"
	"D2PFuzz/utils"
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/urfave/cli/v2"
)

var (
	ProtocolFlag = &cli.StringFlag{
		Name:    "protocol",
		Aliases: []string{"p"},
		Usage:   "Specify the protocol to test",
		Value:   "discv4",
	}
	FileFlag = &cli.StringFlag{
		Name:    "file",
		Aliases: []string{"f"},
		Usage:   "Specify the file containing test data",
	}
	LocationFlag = &cli.StringFlag{
		Name:  "outdir",
		Usage: "Location to place artefacts",
		Value: "/tmp",
	}
	ThreadFlag = &cli.IntFlag{
		Name:  "parallel",
		Usage: "Number of parallel executions to use.",
		Value: runtime.NumCPU(),
	}
	VerbosityFlag = &cli.IntFlag{
		Name:  "verbosity",
		Usage: "sets the verbosity level (-4: DEBUG, 0: INFO, 4: WARN, 8: ERROR)",
		Value: 0,
	}
	SkipTraceFlag = &cli.BoolFlag{
		Name: "skiptrace",
		Usage: "If 'skiptrace' is set to true, then the evms will execute _without_ tracing, and only the final stateroot will be compared after execution.\n" +
			"This mode is faster, and can be used even if the clients-under-test has known errors in the trace-output, \n" +
			"but has a very high chance of missing cases which could be exploitable.",
	}
	TypeFlag = &cli.StringFlag{
		Name:  "type",
		Usage: "Type of packet to generate (e.g., 'ping')",
	}
	CountFlag = &cli.IntFlag{
		Name:  "count",
		Usage: "Number of packets to generate",
		Value: 1,
	}
	traceLengthSA = utils.NewSlidingAverage()
)

func initDiscv4(thread int) []*discv4.UDPv4 {
	var (
		clients  []*discv4.UDPv4
		basePort = 30000
	)

	for i := 0; i < thread; i++ {
		cfg := d2p.Config{
			PrivateKey: d2p.GenKey(),
			Log:        log.Root(),
			Clock:      mclock.System{},
		}
		ip := getLocalIP()
		if ip == nil {
			fmt.Printf("failed to get local IP address for thread %d\n", i)
			continue
		}
		port := basePort + i
		addr := &net.UDPAddr{IP: ip, Port: port}
		udpConn, err := net.ListenUDP("udp", addr)
		if err != nil {
			fmt.Printf("failed to create UDP connection for thread %d: %v\n", i, err)
			continue
		}
		db, _ := enode.OpenDB("")
		nodeKey := d2p.GenKey()
		ln := enode.NewLocalNode(db, nodeKey)
		client, _ := discv4.ListenV4(udpConn, ln, cfg)
		clients = append(clients, client)
	}

	return clients
}

func initDiscv5(thread int) []*discv5.UDPv5 {
	var (
		clients  []*discv5.UDPv5
		basePort = 30000
	)

	for i := 0; i < thread; i++ {
		cfg := d2p.Config{
			PrivateKey: d2p.GenKey(),
			Log:        log.Root(),
			Clock:      mclock.System{},
		}
		ip := getLocalIP()
		if ip == nil {
			fmt.Printf("failed to get local IP address for thread %d\n", i)
			continue
		}
		port := basePort + i
		addr := &net.UDPAddr{IP: ip, Port: port}
		udpConn, err := net.ListenUDP("udp", addr)
		if err != nil {
			fmt.Printf("failed to create UDP connection for thread %d: %v\n", i, err)
			continue
		}
		db, _ := enode.OpenDB("")
		ln := enode.NewLocalNode(db, cfg.PrivateKey)
		client, _ := discv5.ListenV5(udpConn, ln, cfg)
		clients = append(clients, client)
	}

	return clients
}

func initrlpx(thread int, dest *enode.Node) ([]*rlpx.Conn, error) {
	var (
		clients []*rlpx.Conn
	)

	for i := 0; i < thread; i++ {
		fd, err := net.Dial("tcp", fmt.Sprintf("%v:%d", dest.IP(), dest.TCP()))
		if err != nil {
			return nil, err
		}
		client := rlpx.NewConn(fd, dest.Pubkey())
		clients = append(clients, client)
	}

	return clients, nil
}

func GenerateAndExecute(c *cli.Context) error {
	var (
		protocol    = c.String(ProtocolFlag.Name)
		nodeList, _ = GetList(c.String(FileFlag.Name))
	)
	switch protocol {
	case "discv4":
		return discv4Fuzzer(c, nodeList, false)
	case "discv5":
		return discv5Fuzzer(c, nodeList, false)
	case "rlpx":
		return nil
	default:
		return errors.New("unsupported protocol")
	}
}

func discv4Fuzzer(c *cli.Context, nodeList []*enode.Node, cleanupFiles bool) error {
	var (
		clients   = initDiscv4(c.Int(ThreadFlag.Name))
		skipTrace = c.Bool(SkipTraceFlag.Name)
	)
	if len(clients) == 0 {
		return fmt.Errorf("need at least one vm to participate")
	}
	numClients := len(clients)
	log.Info("Fuzzing started...")
	meta := &discv4Meta{
		testCh:  make(chan string, 4), // channel where we'll deliver tests
		clis:    clients,
		targets: nodeList,
		outdir:  c.String(LocationFlag.Name),
	}
	meta.wg.Add(1)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		meta.fuzzingLoop(skipTrace, numClients)
		cancel()
	}()
	meta.wg.Add(1)
	go func() {
		defer meta.wg.Done()
		var (
			tStart    = time.Now()
			ticker    = time.NewTicker(8 * time.Second)
			testCount = uint64(0)
			ticks     = 0
		)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ticks++
				n := meta.numTests.Load()
				testsSinceLastUpdate := n - testCount
				testCount = n
				timeSpent := time.Since(tStart)
				// Update global counter
				globalCount := uint64(0)
				if content, err := os.ReadFile(".fuzzcounter"); err == nil {
					if count, err := strconv.Atoi((string(content))); err == nil {
						globalCount = uint64(count)
					}
				}
				globalCount += testsSinceLastUpdate
				if err := os.WriteFile(".fuzzcounter", []byte(fmt.Sprintf("%d", globalCount)), 0755); err != nil {
					log.Error("Error saving progress", "err", err)
				}
				log.Info("Executing",
					"tests", n,
					"time", common.PrettyDuration(timeSpent),
					"test/s", fmt.Sprintf("%.01f", float64(uint64(time.Second)*n)/float64(timeSpent)),
					"avg steps", fmt.Sprintf("%.01f", traceLengthSA.Avg()),
					"global", globalCount,
				)
				//TODO: Save Client Stats
				//for _, cli := range clients {
				//	log.Info(fmt.Sprintf("Stats %v", cli.Name()), cli.Stats()...)
				//}
				switch ticks {
				case 5:
					// Decrease stats-reporting after 40s
					ticker.Reset(time.Minute)
				case 65:
					// Decrease stats-reporting after one hour
					ticker.Reset(time.Hour)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	// Cancel ability
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigs:
	case <-ctx.Done():
	}
	log.Info("Waiting for processes to exit")
	meta.abort.Store(true)
	cancel()
	meta.wg.Wait()
	return nil
}

func discv5Fuzzer(c *cli.Context, nodeList []*enode.Node, cleanupFiles bool) error {
	var (
		clients   = initDiscv5(c.Int(ThreadFlag.Name))
		skipTrace = c.Bool(SkipTraceFlag.Name)
	)
	if len(clients) == 0 {
		return fmt.Errorf("need at least one vm to participate")
	}
	numClients := len(clients)
	log.Info("Fuzzing started...")
	meta := &discv5Meta{
		testCh:  make(chan string, 4), // channel where we'll deliver tests
		clis:    clients,
		targets: nodeList,
		outdir:  c.String(LocationFlag.Name),
	}
	meta.wg.Add(1)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		meta.fuzzingLoop(skipTrace, numClients)
		cancel()
	}()
	meta.wg.Add(1)
	go func() {
		defer meta.wg.Done()
		var (
			tStart    = time.Now()
			ticker    = time.NewTicker(8 * time.Second)
			testCount = uint64(0)
			ticks     = 0
		)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ticks++
				n := meta.numTests.Load()
				testsSinceLastUpdate := n - testCount
				testCount = n
				timeSpent := time.Since(tStart)
				// Update global counter
				globalCount := uint64(0)
				if content, err := os.ReadFile(".fuzzcounter"); err == nil {
					if count, err := strconv.Atoi((string(content))); err == nil {
						globalCount = uint64(count)
					}
				}
				globalCount += testsSinceLastUpdate
				if err := os.WriteFile(".fuzzcounter", []byte(fmt.Sprintf("%d", globalCount)), 0755); err != nil {
					log.Error("Error saving progress", "err", err)
				}
				log.Info("Executing",
					"tests", n,
					"time", common.PrettyDuration(timeSpent),
					"test/s", fmt.Sprintf("%.01f", float64(uint64(time.Second)*n)/float64(timeSpent)),
					"avg steps", fmt.Sprintf("%.01f", traceLengthSA.Avg()),
					"global", globalCount,
				)
				//TODO: Save Client Stats
				//for _, cli := range clients {
				// log.Info(fmt.Sprintf("Stats %v", cli.Name()), cli.Stats()...)
				//}
				switch ticks {
				case 5:
					// Decrease stats-reporting after 40s
					ticker.Reset(time.Minute)
				case 65:
					// Decrease stats-reporting after one hour
					ticker.Reset(time.Hour)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	// Cancel ability
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigs:
	case <-ctx.Done():
	}
	log.Info("Waiting for processes to exit")
	meta.abort.Store(true)
	cancel()
	meta.wg.Wait()
	return nil
}

type discv4Meta struct {
	abort       atomic.Bool
	testCh      chan string
	wg          sync.WaitGroup
	clis        []*discv4.UDPv4
	targets     []*enode.Node
	numTests    atomic.Uint64
	outdir      string
	notifyTopic string

	deleteFilesWhenDone bool
}

type discv5Meta struct {
	abort       atomic.Bool
	testCh      chan string
	wg          sync.WaitGroup
	clis        []*discv5.UDPv5
	targets     []*enode.Node
	numTests    atomic.Uint64
	outdir      string
	notifyTopic string

	deleteFilesWhenDone bool
}

func (meta *discv4Meta) fuzzingLoop(skipTrace bool, clientCount int) {
	var (
		ready        []int
		taskChannels []chan *task
		resultCh     = make(chan *task)
		cleanCh      = make(chan *cleanTask)
	)
	defer meta.wg.Done()
	defer close(cleanCh)
	// Start n Loops.
	for i, cli := range meta.clis {
		var taskCh = make(chan *task)
		taskChannels = append(taskChannels, taskCh)
		meta.wg.Add(1)
		go meta.cliLoop(cli, taskCh, resultCh)
		ready = append(ready, i)
	}
	return
}

func (meta *discv5Meta) fuzzingLoop(skipTrace bool, clientCount int) {
	var (
		ready        []int
		taskChannels []chan *task
		resultCh     = make(chan *task)
		cleanCh      = make(chan *cleanTask)
	)
	defer meta.wg.Done()
	defer close(cleanCh)
	// Start n Loops.
	for i, cli := range meta.clis {
		var taskCh = make(chan *task)
		taskChannels = append(taskChannels, taskCh)
		meta.wg.Add(1)
		go meta.cliLoop(cli, taskCh, resultCh)
		ready = append(ready, i)
	}
	return
}

func (meta *discv4Meta) cliLoop(cli *discv4.UDPv4, taskCh, resultCh chan *task) {
	return
}

func (meta *discv5Meta) cliLoop(cli *discv5.UDPv5, taskCh, resultCh chan *task) {
	return
}

type task struct {
	// pre-execution fields:
	file      string // file is the input statetest
	testIdx   int    // testIdx is a global index of the test
	vmIdx     int    // vmIdx is a global index of the vm
	skipTrace bool   // skipTrace: if true, ignore output and just exec as fast as possible

	// post-execution fields:
	execSpeed time.Duration
	slow      bool   // set by the executor if the test is deemed slow.
	result    []byte // result is the md5 hash of the execution output
	nLines    int    // number of lines of output
	command   string // command used to execute the test
	err       error  // if error occurred
}

type cleanTask struct {
	slow   string // path to a file considered 'slow'
	remove string // path to a file to be removed
}

func GetList(fName string) ([]*enode.Node, error) {
	file, err := os.Open(fName)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	var nodeList []*enode.Node

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		node := enode.MustParse(line)
		if err != nil {
			return nil, fmt.Errorf("failed to parse enode: %v", err)
		}
		nodeList = append(nodeList, node)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	return nodeList, nil
}

func getLocalIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Error("failed to get local IP address: %v", err)
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP
			}
		}
	}
	return nil
}

func ExecuteGenerator(c *cli.Context) error {
	var (
		protocol    = c.String(ProtocolFlag.Name)
		packetType  = c.String(TypeFlag.Name)
		count       = c.Int(CountFlag.Name)
		nodeList, _ = GetList(c.String(FileFlag.Name))
	)
	switch protocol {
	case "discv4":
		return discv4Generator(packetType, count, nodeList)
	case "discv5":
		return discv5Generator(packetType, count, nodeList)
	case "rlpx":
		return rlpxGenerator(packetType, count, nodeList)
	default:
		return errors.New("unsupported protocol")
	}
}

func discv4Generator(packetType string, count int, nodeList []*enode.Node) error {
	var (
		client *discv4.UDPv4
		node   *enode.Node
	)
	clients := initDiscv4(1)
	client = clients[0]
	node = nodeList[0]
	for i := 0; i < count; i++ {
		packet := client.GenPacket(packetType, node)
		println(packet.String()) // 有问题
		en_packet, hash, err := discv4.Encode(client.GetPri(), packet)
		if err != nil {
			fmt.Printf("encode fail")
		}
		fmt.Sprintf("Encode Packet: %s\nHash: %s", hex.EncodeToString(en_packet), hex.EncodeToString(hash))
	}
	return nil
}

func discv5Generator(packetType string, count int, nodeList []*enode.Node) error {
	var (
		client *discv5.UDPv5
		node   *enode.Node
	)
	clients := initDiscv5(1)
	client = clients[0]
	node = nodeList[0]
	for i := 0; i < count; i++ {
		packet := client.GenPacket(packetType, node)
		println(packet.String())
		toID := node.ID()
		addr := net.JoinHostPort(node.IP().String(), fmt.Sprintf("%d", node.UDP()))
		en_packet, nonce, err := client.EncodePacket(toID, addr, packet, nil)
		if err != nil {
			return fmt.Errorf("encoding error: %v", err)
		}
		fmt.Printf("Encoded Packet: %x\nNonce: %x\n", en_packet, nonce[:])
	}
	return nil
}

func rlpxGenerator(packetType string, count int, nodeList []*enode.Node) error {
	var (
		client *rlpx.Conn
		dest   *enode.Node
	)

	dest = nodeList[0]
	clients, err := initrlpx(1, dest)
	if err != nil {
		return errors.New("clients init error")
	}
	client = clients[0]

	for i := 0; i < count; i++ {
		packet := client.GenPacket(packetType)
		println(packet)
	}

	return nil
}
