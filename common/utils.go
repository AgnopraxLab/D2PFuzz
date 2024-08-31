package common

import (
	"D2PFuzz/d2p"
	"D2PFuzz/d2p/protocol/discv4"
	"D2PFuzz/d2p/protocol/discv5"
	"D2PFuzz/d2p/protocol/eth"
	"D2PFuzz/utils"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover/v5wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
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

func initeth(thread int, dest *enode.Node, dir string) ([]*eth.Suite, error) {
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
		protocol = c.String(ProtocolFlag.Name)
		node, _  = GetList(c.String(FileFlag.Name))
	)
	switch protocol {
	case "discv4":
		return discv4Fuzzer(c, node)
	case "discv5":
		return discv5Fuzzer(c, node, false)
	case "eth":
		return ethFuzzer(c, node)
	default:
		return errors.New("unsupported protocol")
	}
}

func discv4Fuzzer(c *cli.Context, node *enode.Node) error {
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
		targets: node,
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

func discv5Fuzzer(c *cli.Context, node *enode.Node, cleanupFiles bool) error {
	var (
		clients   = initDiscv5(c.Int(ThreadFlag.Name))
		skipTrace = c.Bool(SkipTraceFlag.Name)
	)
	if len(clients) == 0 {
		return fmt.Errorf("need at least one vm to participate")
	}
	log.Info("Fuzzing started...")
	meta := &discv5Meta{
		testCh:  make(chan string, 4), // channel where we'll deliver tests
		clis:    clients,
		targets: node,
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

func ethFuzzer(c *cli.Context, node *enode.Node) error {
	var (
		clients, err = initeth(c.Int(ThreadFlag.Name), node, c.String(LocationFlag.Name))
		skipTrace    = c.Bool(SkipTraceFlag.Name)
	)
	if err != nil {
		return fmt.Errorf("failed to initialize eth clients: %v", err)
	}
	if len(clients) == 0 {
		return fmt.Errorf("need at least one vm to participate")
	}
	log.Info("Fuzzing started...")
	meta := &ethMeta{
		testCh:  make(chan string, 4), // channel where we'll deliver tests
		clis:    clients,
		targets: node,
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

type discv4Meta struct {
	abort       atomic.Bool
	testCh      chan string
	wg          sync.WaitGroup
	clis        []*discv4.UDPv4
	targets     *enode.Node
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
	targets     *enode.Node
	numTests    atomic.Uint64
	outdir      string
	notifyTopic string

	deleteFilesWhenDone bool
}

type ethMeta struct {
	abort       atomic.Bool
	testCh      chan string
	wg          sync.WaitGroup
	clis        []*eth.Suite
	targets     *enode.Node
	numTests    atomic.Uint64
	outdir      string
	notifyTopic string

	deleteFilesWhenDone bool
}

func (meta *discv4Meta) fuzzingLoop(skipTrace bool) {
	defer meta.wg.Done()

	// 启动多个并发任务，分别为每个 cli 执行 cliLoop 函数
	for i, cli := range meta.clis {
		meta.wg.Add(1)
		// 创建一个新的保存 seed 的路径
		seedDir := filepath.Join(meta.outdir, "discv4", fmt.Sprintf("cli-%d", i), "seed")
		if err := os.MkdirAll(seedDir, 0755); err != nil {
			fmt.Printf("Error creating seed directory: %v\n", err)
			return
		}

		go meta.cliLoop(cli, seedDir)
	}
}

func (meta *discv5Meta) fuzzingLoop(skipTrace bool) {
	defer meta.wg.Done()

	// 启动多个并发任务，分别为每个 cli 执行 cliLoop 函数
	for i, cli := range meta.clis {
		meta.wg.Add(1)
		// 创建一个新的保存 seed 的路径
		seedDir := filepath.Join(meta.outdir, "discv5", fmt.Sprintf("cli-%d", i), "seed")
		if err := os.MkdirAll(seedDir, 0755); err != nil {
			fmt.Printf("Error creating seed directory: %v\n", err)
			return
		}

		go meta.cliLoop(cli, seedDir)
	}
}

func (meta *ethMeta) fuzzingLoop(skipTrace bool) {
	defer meta.wg.Done()

	for i, cli := range meta.clis {
		meta.wg.Add(1)
		seedDir := filepath.Join(meta.outdir, "eth", fmt.Sprintf("cli-%d", i), "seed")
		if err := os.MkdirAll(seedDir, 0755); err != nil {
			fmt.Printf("Error creating seed directory: %v\n", err)
			return
		}

		go meta.cliLoop(cli, seedDir)
	}
}

func (meta *discv4Meta) cliLoop(cli *discv4.UDPv4, seedDir string) {
	defer meta.wg.Done()

	// 定义一个 种子队列
	var seedQueue []*discv4.V4Seed
	initSeed, err := cli.CreateSeed(meta.targets)
	if err != nil {
		fmt.Printf("Error initSeed: %v\n", err)
	}

	initSeed, err = cli.RunPacketTest(initSeed, meta.targets)
	if err != nil {
		fmt.Printf("Error starting client packet test: %v\n", err)
	}

	seedQueue = append(seedQueue, initSeed)
	err = meta.saveSeed(seedDir, initSeed)
	if err != nil {
		fmt.Printf("Error starting client packet test: %v\n", err)
	}

	for {
		seed := cli.SelectSeed(seedQueue)
		newSeed, err := cli.RunPacketTest(seed, meta.targets)
		if err != nil {
			fmt.Printf("Error starting client packet test: %v\n", err)
		}
		seedQueue = append(seedQueue, newSeed)
		err = meta.saveSeed(seedDir, newSeed)
		if err != nil {
			fmt.Printf("Error starting client packet test: %v\n", err)
		}
	}
}

func (meta *discv5Meta) cliLoop(cli *discv5.UDPv5, seedDir string) {
	defer meta.wg.Done()

	// 定义一个 种子队列
	var seedQueue []*discv5.V5Seed
	initSeed, err := cli.CreateSeed(meta.targets)
	if err != nil {
		fmt.Printf("Error initSeed: %v\n", err)
	}

	initSeed, err = cli.RunPacketTest(initSeed, meta.targets)
	if err != nil {
		fmt.Printf("Error starting client packet test: %v\n", err)
	}

	seedQueue = append(seedQueue, initSeed)
	err = meta.saveSeed(seedDir, initSeed)
	if err != nil {
		fmt.Printf("Error starting client packet test: %v\n", err)
	}

	for {
		seed := cli.SelectSeed(seedQueue)
		newSeed, err := cli.RunPacketTest(seed, meta.targets)
		if err != nil {
			fmt.Printf("Error starting client packet test: %v\n", err)
		}
		seedQueue = append(seedQueue, newSeed)
		err = meta.saveSeed(seedDir, newSeed)
		if err != nil {
			fmt.Printf("Error starting client packet test: %v\n", err)
		}
	}
}

// 没有完成！！！
func (meta *ethMeta) cliLoop(cli *eth.Suite, seedDir string) {
	defer meta.wg.Done()
}

func (meta *ethMeta) saveSeed(seedDir string) error {
	// Implement seed saving logic here
	return nil
}

func (meta *discv4Meta) saveSeed(seedDir string, seed *discv4.V4Seed) error {
	// 将V4Seed对象转换为JSON字符串
	jsonData, err := json.MarshalIndent(seed.Series, "", "  ")
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("%s.json", seed.ID)

	// 构建完整的文件路径
	filePath := filepath.Join(seedDir, filename)

	// 将JSON字符串写入文件
	err = ioutil.WriteFile(filePath, jsonData, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("Seed saved to %s\n", filePath)
	return nil
}

func (meta *discv5Meta) saveSeed(seedDir string, seed *discv5.V5Seed) error {
	// 将V4Seed对象转换为JSON字符串
	jsonData, err := json.MarshalIndent(seed.Series, "", "  ")
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("%s.json", seed.ID)

	// 构建完整的文件路径
	filePath := filepath.Join(seedDir, filename)

	// 将JSON字符串写入文件
	err = ioutil.WriteFile(filePath, jsonData, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("Seed saved to %s\n", filePath)
	return nil
}

func GetList(fName string) (*enode.Node, error) {
	content, err := ioutil.ReadFile(fName)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	// 去除可能的 BOM 和空白字符
	cleanContent := strings.TrimSpace(string(content))
	cleanContent = strings.TrimPrefix(cleanContent, "\uFEFF") // 移除 UTF-8 BOM

	if !strings.HasPrefix(cleanContent, "enr:") {
		return nil, fmt.Errorf("invalid ENR: missing 'enr:' prefix")
	}

	node, err := enode.Parse(enode.ValidSchemes, cleanContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse enode: %v", err)
	}

	return node, nil
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
		//chainDir    = c.String(ChainDirFlag.Name)
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
		// 获取当前文件的路径
		_, currentFile, _, _ := runtime.Caller(0)

		// 获取项目根目录
		projectRoot := filepath.Dir(filepath.Dir(currentFile))

		// 构造 test/ethdata 的绝对路径
		dir := filepath.Join(projectRoot, "test", "ethdata")
		genTestFlag := true
		packetTypeInt, err := strconv.Atoi(packetType)

		if err != nil {
			// 处理错误，例如 packetType 不是一个有效的整数字符串
			fmt.Println("转换错误:", err)
		}
		return ethGenerator(dir, packetTypeInt, count, nodeList, genTestFlag)
	default:
		return errors.New("unsupported protocol")
	}
}

func discv4Generator(packetType string, count int, node *enode.Node, genTest bool) ([]discv4.Packet, error) {
	var (
		client *discv4.UDPv4
	)
	clients := initDiscv4(1)
	client = clients[0]
	reqQueue := make([]discv4.Packet, 0, count)

	for i := 0; i < count; i++ {
		req := client.GenPacket(packetType, node)
		reqQueue = append(reqQueue, req)
		// todo: need Fuzzer send generator just return array of raw packet
		if genTest {
			data, _ := json.MarshalIndent(req, "", "")
			fmt.Printf(string(data))

			// 根据数据包类型设置预期的响应类型
			var expectedResponseType byte
			switch packetType {
			case "ping":
				expectedResponseType = discv4.PongPacket
			case "findnode":
				expectedResponseType = discv4.NeighborsPacket
			case "ENRRequest":
				expectedResponseType = discv4.ENRResponsePacket
			// 添加其他数据包类型的处理...
			default:
				fmt.Printf("Unknown packet type: %s\n", packetType)
				continue
			}

			// 设置回复匹配器
			rm := client.Pending(node.ID(), node.IP(), expectedResponseType, func(p discv4.Packet) (matched bool, requestDone bool) {
				// 这里可以添加更详细的匹配逻辑
				fmt.Printf("Received response: %+v\n", p)
				return true, true
			})

			// 发送数据包
			hash := client.Send(node, req)
			fmt.Printf("Sent packet with hash: %x\n", hash)

			// 使用新的 WaitForResponse 方法等待响应
			err := rm.WaitForResponse(5 * time.Second)
			if err != nil {
				if err.Error() == "timeout waiting for response" {
					fmt.Println("Timeout waiting for response")
				} else {
					fmt.Printf("Error waiting for response: %v\n", err)
				}
			}
		}
		time.Sleep(time.Second)
	}

	return reqQueue, nil
}

func discv5Generator(packetType string, count int, node *enode.Node, genTest bool) ([]discv5.Packet, error) {
	var (
		client *discv5.UDPv5
	)
	clients := initDiscv5(1)
	client = clients[0]

	reqQueues := make([]discv5.Packet, 0, count)
	nonceQueue := make([]discv5.Nonce, 0, count)

	for i := 0; i < count; i++ {
		req := client.GenPacket(packetType, node)
		//println(req.String())

		fmt.Printf("lnIP: %v\n", client.LocalNode().Node().IP().String())

		// 在调用 EncodePacket 之前打印输入
		fmt.Printf("EncodePacket Input:\n")
		fmt.Printf("packet: %+v\n", req)
		fmt.Printf("challenge: nil\n")

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

func ethGenerator(dir string, packetType, count int, nodeList *enode.Node, genTestFlag bool) error {
	clients, err := initeth(1, nodeList, dir)
	if err != nil {
		return errors.New("clients init error")
	}
	client := clients[0]

	state := eth.NewOracleState() // 创建Oracle状态

	// 初始化 PacketSpecification
	spec := &eth.PacketSpecification{
		BlockNumbers: []int{10, 20, 30},
		BlockHashes:  make([]common.Hash, 3),
	}
	// 生成一些随机的区块哈希
	for i := 0; i < 3; i++ {
		hash := crypto.Keccak256([]byte(fmt.Sprintf("hash%d", i)))
		spec.BlockHashes[i] = common.BytesToHash(hash[:])
	}

	for i := 0; i < count; i++ {
		packet, err := client.GenPacket(packetType, spec)
		if err != nil {
			return errors.New("GenPacket fail")
		}

		// 使用Oracle检查并修正数据包
		checkedPacket, err := eth.OracleCheck(packet, state)
		if err != nil {
			return errors.New("oracle check fail")
		}

		state.PacketHistory = append(state.PacketHistory, checkedPacket)
	}

	// 在生成所有包后进行多包逻辑检验
	err = eth.MultiPacketCheck(state)
	if err != nil {
		return errors.New("multi-packet check fail")
	}
	// 输出修正后的包
	for _, packet := range state.PacketHistory {
		println(packet)
	}

	return nil
}

func decodeDiscv5Packet(encodedPacket []byte, fromAddr *net.UDPAddr) (enode.ID, *enode.Node, v5wire.Packet, error) {
	var (
		client *discv5.UDPv5
	)
	// 创建一个新的 UDPv5 实例用于解码
	clients := initDiscv5(1)
	client = clients[0]
	defer client.Close()

	// 使用 client 的 DecodePacket 方法来解码数据包
	return client.DecodePacket(encodedPacket, fromAddr.String())
}
