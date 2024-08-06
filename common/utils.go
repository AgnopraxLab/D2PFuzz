package common

import (
	"D2PFuzz/d2p"
	"D2PFuzz/d2p/protocol/discv4"
	"D2PFuzz/d2p/protocol/discv5"
	"D2PFuzz/d2p/protocol/eth"
	"D2PFuzz/utils"
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"math/rand"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/urfave/cli/v2"
)

var (
	GenTestFlag = &cli.BoolFlag{
		Name:    "genTest",
		Aliases: []string{"gt"},
		Usage:   "Specify the protocol to test",
		Value:   true,
	}
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
		Name:    "type",
		Aliases: []string{"t"},
		Usage:   "Type of packet to generate (e.g., 'ping')",
	}
	CountFlag = &cli.IntFlag{
		Name:    "count",
		Aliases: []string{"c"},
		Usage:   "Number of packets to generate",
		Value:   1,
	}
	ChainDirFlag = &cli.StringFlag{
		Name:  "chain",
		Usage: "Test chain directory (required)",
	}
	traceLengthSA = utils.NewSlidingAverage()
)

func initDiscv4(thread int) []*discv4.UDPv4 {
	var (
		clients  []*discv4.UDPv4
		basePort = 40000
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
		ln.Set(enr.IP(ip))
		ln.Set(enr.UDP(uint16(port)))
		client, _ := discv4.ListenV4(udpConn, ln, cfg)
		clients = append(clients, client)
	}

	return clients
}

// Suite is the discv5 test suite.
type Suite struct {
	Dest    *enode.Node
	Listen1 string // listening addresses
}

func initDiscv5(thread int) []*discv5.UDPv5 {
	var (
		clients           []*discv5.UDPv5
		basePort          = 50000
		DefaultProtocolID = [6]byte{'d', 'i', 's', 'c', 'v', '5'}
	)

	for i := 0; i < thread; i++ {
		cfg := d2p.Config{
			PrivateKey:   d2p.GenKey(),
			V5ProtocolID: &DefaultProtocolID,
			Log:          log.Root(),
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
		ln := enode.NewLocalNode(db, cfg.PrivateKey)
		ln.Set(enr.IP(ip))
		ln.Set(enr.UDP(uint16(port)))
		client, _ := discv5.ListenV5(udpConn, ln, cfg)
		clients = append(clients, client)
	}

	return clients
}

func initeth(thread int, dest []*enode.Node, dir string) ([]*eth.Suite, error) {
	var (
		clients []*eth.Suite
	)

	for i := 0; i < thread; i++ {
		pri, _ := crypto.GenerateKey()
		client, err := eth.NewSuite(dest, dir, pri)
		if err != nil {
			return nil, errors.New("New Suite fail")
		}
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
		return discv4Fuzzer(c, nodeList)
	case "discv5":
		return discv5Fuzzer(c, nodeList, false)
	case "eth":
		return nil
	default:
		return errors.New("unsupported protocol")
	}
}

func discv4Fuzzer(c *cli.Context, nodeList []*enode.Node) error {
	var (
		clients   = initDiscv4(c.Int(ThreadFlag.Name))
		skipTrace = c.Bool(SkipTraceFlag.Name)
	)
	if len(clients) == 0 {
		return fmt.Errorf("need at least one vm to participate")
	}
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
		meta.fuzzingLoop(skipTrace)
		cancel()
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

func (meta *discv4Meta) fuzzingLoop(skipTrace bool) {
	defer meta.wg.Done()

	// 创建一个新的保存 seed 的路径
	seedDir := filepath.Join(meta.outdir, "discv4", "seed")
	if err := os.MkdirAll(seedDir, 0755); err != nil {
		fmt.Printf("Error creating seed directory: %v\n", err)
		return
	}

	//// 初始化一个 seed 并将其以文件名为当前时间戳的前提下保存在 seedDir 目录下
	//...
	//
	//// 实现一个大循环来不断让 cli 执行不同的 seed
	//for{
	//	// 从 seedDir 路径下的文件中随机选择一个 seed 文件
	//	seed :=
	//	for i, cli := range meta.clis {
	//		meta.wg.Add(1)
	//		go meta.cliLoop(cli, seed)
	//	}
	//}
	// 初始化一个 seed 并将其以文件名为当前时间戳的前提下保存在 seedDir 目录下
	seed := []byte("initial seed data") // 初始化种子数据
	seedFile := filepath.Join(seedDir, fmt.Sprintf("%d.seed", time.Now().Unix()))
	if err := ioutil.WriteFile(seedFile, seed, 0644); err != nil {
		fmt.Printf("Error writing seed file: %v\n", err)
		return
	}

	// 实现一个大循环来不断让 cli 执行不同的 seed
	for {
		// 获取 seedDir 路径下的所有文件
		files, err := ioutil.ReadDir(seedDir)
		if err != nil {
			fmt.Printf("Error reading seed directory: %v\n", err)
			return
		}

		// 从 seedDir 路径下的文件中随机选择一个 seed 文件
		rand.Seed(time.Now().UnixNano())
		randomFile := files[rand.Intn(len(files))]
		seedPath := filepath.Join(seedDir, randomFile.Name())

		// 读取选中的种子文件
		seed, err := ioutil.ReadFile(seedPath)
		if err != nil {
			fmt.Printf("Error reading seed file: %v\n", err)
			return
		}

		// 启动多个并发任务，分别为每个 cli 执行 cliLoop 函数
		for _, cli := range meta.clis {
			meta.wg.Add(1)
			go meta.cliLoop(cli, seed)
		}
	}
}
}

func (meta *discv5Meta) fuzzingLoop(skipTrace bool, clientCount int) {
	var (
		ready []int
	)
	defer meta.wg.Done()
	// Start n Loops.
	for i, cli := range meta.clis {
		meta.wg.Add(1)
		go meta.cliLoop(cli)
		ready = append(ready, i)
	}
	return
}

func (meta *discv4Meta) cliLoop(cli *discv4.UDPv4, seed string) {
	defer meta.wg.Done()
	_, err := cli.RunPacketTest(seed)
	if err != nil {
		log.Error("Error starting client", "err", err, "client")
	}
	log.Debug("vmloop exiting")
}

func (meta *discv5Meta) cliLoop(cli *discv5.UDPv5) {
	return
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
		chainDir    = c.String(ChainDirFlag.Name)
		genTestFlag = c.Bool(GenTestFlag.Name)
	)
	switch protocol {
	case "discv4":
		if _, err := discv4Generator(packetType, count, nodeList, genTestFlag); err != nil {
			panic(fmt.Errorf("can't generat %v: %v", packetType, err))
		}
		return nil
	case "discv5":
		if _, err := discv5Generator(packetType, count, nodeList, genTestFlag); err != nil {
			panic(fmt.Errorf("can't generat %v: %v", packetType, err))
		}
		return nil
	case "eth":
		return ethGenerator(chainDir, 0, count, nodeList, genTestFlag)
	default:
		return errors.New("unsupported protocol")
	}
}

func discv4Generator(packetType string, count int, nodeList []*enode.Node, genTest bool) ([]discv4.Packet, error) {
	var (
		client *discv4.UDPv4
		node   *enode.Node
	)
	clients := initDiscv4(1)
	client = clients[0]
	node = nodeList[0]
	reqQueue := make([]discv4.Packet, 0, count)

	for i := 0; i < count; i++ {
		req := client.GenPacket(packetType, node)
		//println(req.String()) // 有问题
		reqQueue = append(reqQueue, req)
		// todo: need Fuzzer send generator just return array of raw packet
		if genTest {
			data, _ := json.MarshalIndent(req, "", "")
			fmt.Printf(string(data))
			client.Send(node, req)
		}
		time.Sleep(time.Second)
	}

	return reqQueue, nil
}

func discv5Generator(packetType string, count int, nodeList []*enode.Node, genTest bool) ([]discv5.Packet, error) {
	var (
		client *discv5.UDPv5
		node   *enode.Node
	)
	clients := initDiscv5(1)
	client = clients[0]
	node = nodeList[0]

	reqQueues := make([]discv5.Packet, 0, count)
	nonceQueue := make([]discv5.Nonce, 0, count)

	for i := 0; i < count; i++ {
		req := client.GenPacket(packetType, node)
		println(req.String())

		fmt.Printf("lnIP: %v\n", client.LocalNode().Node().IP().String())

		// 在调用 EncodePacket 之前打印输入
		fmt.Printf("EncodePacket Input:\n")
		fmt.Printf("  packet: %+v\n", req)
		fmt.Printf("  challenge: nil\n")

		// 调用 EncodePacket
		//en_packet, nonce, err := client.EncodePacket(node.ID(), addr, packet, nil)
		if genTest {
			data, _ := json.MarshalIndent(req, "", "")
			fmt.Printf(string(data))
			nonce, err := client.Send(node, req, nil)
			if err != nil {
				panic(fmt.Errorf("can't send %v: %v", packetType, err))
			}
			nonceQueue = append(nonceQueue, nonce)
		}
		reqQueues = append(reqQueues, req)

		time.Sleep(time.Second)
	}
	return reqQueues, nil
}

func ethGenerator(dir string, packetType, count int, nodeList []*enode.Node, genTest bool) error {

	clients, err := initeth(1, nodeList, dir)
	if err != nil {
		return errors.New("clients init error")
	}
	client := clients[0]

	for i := 0; i < count; i++ {

		packet, err := client.GenPacket(packetType)
		if err != nil {
			return errors.New("GenPacket fail")
		}
		println(packet)
	}

	return nil
}
