package common

import (
	"D2PFuzz/d2p"
	"D2PFuzz/d2p/protocol/discv4"
	"bufio"
	"fmt"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/urfave/cli/v2"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

var (
	protocolFlag = &cli.StringFlag{
		Name:    "protocol",
		Aliases: []string{"p"},
		Usage:   "Specify the protocol to test",
		Value:   "discv4",
	}
	fileFlag = &cli.StringFlag{
		Name:     "file",
		Aliases:  []string{"f"},
		Usage:    "Specify the file containing test data",
		Required: true,
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
)

func initCli(c *cli.Context) []d2p.ConnClient {
	var (
		thread   = c.Int(ThreadFlag.Name)
		protocol = c.String(protocolFlag.Name)
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
		clients     = initCli(c)
		skipTrace   = c.Bool(SkipTraceFlag.Name)
		numClients  = len(clients)
		nodeList, _ = GetList(c.String(fileFlag.Name))
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
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		meta.fuzzingLoop(skipTrace, numClients)
		cancel()
	}()
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

func (meta *testMeta) fuzzingLoop(skipTrace bool) {
	var (
		ready        []int
		testIndex    = 0
		taskChannels []chan *task
		resultCh     = make(chan *task)
		cleanCh      = make(chan *cleanTask)
	)
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
