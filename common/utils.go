package common

import (
	"D2PFuzz/d2p"
	"D2PFuzz/d2p/protocol/discv4"
	utils "D2PFuzz/util"
	"bufio"
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/urfave/cli/v2"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
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

func initCli(protocol string, thread int) []d2p.ConnClient {
	var (
		clients  []d2p.ConnClient
		basePort = 30000
	)

	switch protocol {
	case "discv4":
		for i := 0; i < thread; i++ {
			cfg := discv4.Config{
				PrivateKey:   d2p.GenKey(),
				Unhandled:    make(chan discv4.ReadPacket, 10),
				Log:          log.Root(),
				ValidSchemes: enode.ValidSchemes,
				Clock:        mclock.System{},
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

	case "discv5":
		break
	default:
		fmt.Printf("Unknown protocol: %s\n", protocol)
	}

	return clients
}

func ExecuteFuzzer(c *cli.Context, cleanupFiles bool) error {
	var (
		clients     = initCli(c.String(ProtocolFlag.Name), c.Int(ThreadFlag.Name))
		skipTrace   = c.Bool(SkipTraceFlag.Name)
		numClients  = len(clients)
		nodeList, _ = GetList(c.String(FileFlag.Name))
	)
	if len(clients) == 0 {
		return fmt.Errorf("need at least one vm to participate")
	}
	log.Info("Fuzzing started...")
	meta := &testMeta{
		testCh:  make(chan string, 4), // channel where we'll deliver tests
		cli:     clients,
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

type testMeta struct {
	abort       atomic.Bool
	testCh      chan string
	wg          sync.WaitGroup
	cli         []d2p.ConnClient
	targets     []*enode.Node
	numTests    atomic.Uint64
	outdir      string
	notifyTopic string

	deleteFilesWhenDone bool
}

func (meta *testMeta) fuzzingLoop(skipTrace bool, clientCount int) {
	skipTrace = true
	clientCount = 0
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

func ExecuteGenerator(c *cli.Context) {
	var (
		protocol   = c.String(ProtocolFlag.Name)
		packetType = c.String(TypeFlag.Name)
		count      = c.Int(CountFlag.Name)
		target     = c.String(FileFlag.Name)
	)

	cli := initCli(protocol, 1)
	for i := 0; i < count; i++ {
		packet := cli.GeneratePacket(packetType, protocol)
		if target != "" {
			// Simulate sending the packet to the target
			fmt.Printf("Sending packet to %s: %s\n", target, packet)
			// Implement actual sending logic here
		} else {
			// Print the packet
			fmt.Println(packet)
		}
	}
}

func (cli d2p.ConnClient) GeneratePacket(packetType string) string {
	switch packetType {
	case "ping":
		return "DiscV4 Ping Packet"
	case "pong":
		return "DiscV4 Pong Packet"
	// Add more packet types as needed
	default:
		return "Unknown Packet Type"
	}
}
