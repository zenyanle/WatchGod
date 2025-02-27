package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// 2025-02-27 05:30:01
// zenyanle

// 常量定义
const (
	MaxPacketSize = 256 // 与内核程序保持一致
	VMwareOffset  = 24  // VMware头部默认偏移量
)

// 命令行参数
var (
	interfaceName string
	showHex       bool
	verbose       bool
	debug         bool
	vmwareOffset  int  // VMware头部偏移选项
	detectVMware  bool // 自动检测VMware头部
	maxBytes      int  // 最大显示字节数
)

// PacketMetadata 对应内核传来的元数据
type PacketMetadata struct {
	PacketSize   uint32
	CapturedSize uint32
	Protocol     uint32 // 协议类型
	Flags        uint32
	Timestamp    uint64
}

// EthernetHeader 以太网头部
type EthernetHeader struct {
	DstMAC    [6]byte
	SrcMAC    [6]byte
	EtherType uint16
}

// IPv4Header IPv4头部
type IPv4Header struct {
	VersionIHL          uint8 // 版本(4位) + 头部长度(4位)
	TOS                 uint8
	TotalLen            uint16
	ID                  uint16
	FlagsFragmentOffset uint16 // 标志(3位) + 片偏移(13位)
	TTL                 uint8
	Protocol            uint8
	Checksum            uint16
	SrcIP               [4]byte
	DstIP               [4]byte
}

// TCPHeader TCP头部
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8 // 高4位 + 保留位和标志
	Flags      uint8
	Window     uint16
	Checksum   uint16
	UrgPtr     uint16
}

// UDPHeader UDP头部
type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

// PacketPrinter 数据包打印器
type PacketPrinter struct {
	showHex      bool
	verbose      bool
	vmwareOffset int
	detectVMware bool
	maxBytes     int
	stats        struct {
		packets uint64
		bytes   uint64
	}
	startTime time.Time
}

// NewPacketPrinter 创建新的数据包打印器
func NewPacketPrinter(showHex, verbose bool, vmwareOffset int, detectVMware bool, maxBytes int) *PacketPrinter {
	return &PacketPrinter{
		showHex:      showHex,
		verbose:      verbose,
		vmwareOffset: vmwareOffset,
		detectVMware: detectVMware,
		maxBytes:     maxBytes,
		startTime:    time.Now(),
	}
}

// detectRealEthernetOffset 尝试找出真正的以太网头在哪里
func (p *PacketPrinter) detectRealEthernetOffset(payload []byte) int {
	// 如果指定了偏移量且不需要检测，直接返回
	if p.vmwareOffset > 0 && !p.detectVMware {
		return p.vmwareOffset
	}

	// 默认偏移
	offset := p.vmwareOffset
	if offset <= 0 {
		offset = VMwareOffset // 使用默认值
	}

	// 如果数据包太短，无法处理
	if len(payload) < 14 {
		return 0
	}

	// 如果已经是标准的以太网MAC地址格式，直接返回0
	eth := &EthernetHeader{}
	if err := binary.Read(bytes.NewReader(payload), binary.BigEndian, eth); err == nil {
		mac1 := net.HardwareAddr(eth.SrcMAC[:])
		mac2 := net.HardwareAddr(eth.DstMAC[:])

		// 简单检查MAC地址是否看起来有效
		if isValidMACAddress(mac1.String()) && isValidMACAddress(mac2.String()) {
			if debug {
				log.Printf("Detected valid MACs at offset 0: %s, %s", mac1, mac2)
			}
			return 0
		}
	}

	// 寻找VMware MAC特征 (如00:0c:29或00:50:56开头)
	for i := 0; i <= len(payload)-14; i += 2 {
		// 尝试第i个位置是否有VMware MAC地址
		if i+6 < len(payload) &&
			((payload[i] == 0x00 && payload[i+1] == 0x0c && payload[i+2] == 0x29) ||
				(payload[i] == 0x00 && payload[i+1] == 0x50 && payload[i+2] == 0x56)) {

			// 可能是源MAC或目标MAC，检查是否像以太网帧结构
			for j := i - 6; j >= 0 && j <= i; j++ {
				if j+12 < len(payload) {
					possibleEthType := binary.BigEndian.Uint16(payload[j+12 : j+14])
					// 常见EtherType: 0x0800(IPv4), 0x0806(ARP), 0x86DD(IPv6)
					if possibleEthType == 0x0800 || possibleEthType == 0x0806 || possibleEthType == 0x86DD {
						// 提取可能的MAC地址
						dstMac := net.HardwareAddr(payload[j : j+6])
						srcMac := net.HardwareAddr(payload[j+6 : j+12])

						if isValidMACAddress(dstMac.String()) && isValidMACAddress(srcMac.String()) {
							if debug {
								log.Printf("Found likely ethernet frame at offset %d: %s -> %s, EtherType: 0x%04x",
									j, srcMac, dstMac, possibleEthType)
							}
							return j
						}
					}
				}
			}
		}
	}

	// 如果无法检测，返回默认偏移
	return offset
}

// isValidMACAddress 检查MAC地址是否有效
func isValidMACAddress(mac string) bool {
	// 简单检查：MAC地址格式为xx:xx:xx:xx:xx:xx
	pattern := regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`)
	if !pattern.MatchString(mac) {
		return false
	}

	// 排除全0或全F的MAC
	zeroPattern := regexp.MustCompile(`^([0]{2}[:-]){5}([0]{2})$`)
	ffPattern := regexp.MustCompile(`^([Ff]{2}[:-]){5}([Ff]{2})$`)
	return !zeroPattern.MatchString(mac) && !ffPattern.MatchString(mac)
}

// PrintPacket 打印数据包内容，处理VMware偏移
func (p *PacketPrinter) PrintPacket(meta *PacketMetadata, payload []byte) {
	// 更新统计信息
	p.stats.packets++
	p.stats.bytes += uint64(meta.PacketSize)

	// 打印数据包信息
	fmt.Printf("\n=== Packet Captured at %s ===\n",
		time.Unix(0, int64(meta.Timestamp)).Format("2006-01-02 15:04:05.000000"))

	// 限制处理的最大字节数(确保不超过实际捕获大小)
	actualCaptured := min(int(meta.CapturedSize), len(payload))
	if actualCaptured > p.maxBytes {
		if debug {
			log.Printf("Limiting payload from %d to %d bytes", actualCaptured, p.maxBytes)
		}
		actualCaptured = p.maxBytes
		payload = payload[:actualCaptured]
	}

	fmt.Printf("Original Size: %d bytes, Captured: %d bytes\n",
		meta.PacketSize, actualCaptured)

	// 检测真实以太网帧的偏移量
	offset := p.detectRealEthernetOffset(payload)

	if debug {
		if offset > 0 {
			fmt.Printf("VMware header detected, using offset: %d bytes\n", offset)
		}
		fmt.Printf("Protocol from metadata: 0x%04x\n", meta.Protocol)
	}

	// 解析以太网头部
	if len(payload) < offset+14 {
		fmt.Println("Packet too short for Ethernet header after offset")

		// 如果开启调试，显示原始内容
		if debug {
			fmt.Printf("Raw data (%d bytes): %s\n", len(payload),
				hex.EncodeToString(payload))
		}
		return
	}

	// 获取实际的以太网帧数据
	realEthernet := payload[offset:]

	// 确保只处理有效的以太网帧数据
	if len(realEthernet) < 14 {
		fmt.Println("Ethernet frame too short after offset adjustment")
		return
	}

	eth := &EthernetHeader{}
	reader := bytes.NewReader(realEthernet)
	if err := binary.Read(reader, binary.BigEndian, eth); err != nil {
		fmt.Printf("Error reading Ethernet header: %v\n", err)
		return
	}

	fmt.Printf("\nEthernet:\n")
	fmt.Printf("  Src MAC: %s\n", net.HardwareAddr(eth.SrcMAC[:]))
	fmt.Printf("  Dst MAC: %s\n", net.HardwareAddr(eth.DstMAC[:]))
	fmt.Printf("  Type: 0x%04x\n", eth.EtherType)

	// 根据EtherType解析上层协议
	if eth.EtherType == 0x0800 && len(realEthernet) >= 34 { // 以太网头(14) + IP头(20)
		p.parseIPv4(realEthernet[14:])
	} else if eth.EtherType == 0x0806 && len(realEthernet) >= 42 { // ARP
		p.parseARP(realEthernet[14:])
	} else if eth.EtherType == 0x86DD && len(realEthernet) >= 54 { // IPv6
		p.parseIPv6(realEthernet[14:])
	}

	// 显示十六进制数据
	if p.showHex {
		// 如果有VMware头，且开启了详细模式
		if offset > 0 && p.verbose {
			fmt.Println("\nFull Hex dump (including VMware header):")
			p.printHexDump(payload)

			fmt.Println("\nEthernet frame Hex dump (after VMware header):")
			p.printHexDump(realEthernet)
		} else {
			// 否则只显示以太网帧部分
			fmt.Println("\nHex dump:")
			p.printHexDump(realEthernet)
		}
	}

	// 定期打印统计信息
	elapsed := time.Since(p.startTime)
	if elapsed.Seconds() >= 1 {
		p.printStats()
		p.startTime = time.Now()
		p.stats.packets = 0
		p.stats.bytes = 0
	}
}

// parseIPv4 解析IPv4数据包
func (p *PacketPrinter) parseIPv4(payload []byte) {
	if len(payload) < 20 {
		fmt.Println("IPv4 header too short")
		return
	}

	ipv4 := &IPv4Header{}
	reader := bytes.NewReader(payload)
	if err := binary.Read(reader, binary.BigEndian, ipv4); err != nil {
		fmt.Printf("Error reading IPv4 header: %v\n", err)
		return
	}

	// 从VersionIHL字段解析版本和头部长度
	version := (ipv4.VersionIHL >> 4) & 0xF
	ihl := ipv4.VersionIHL & 0xF
	headerLen := int(ihl) * 4

	fmt.Printf("\nIPv4:\n")
	fmt.Printf("  Version: %d\n", version)
	fmt.Printf("  Header Length: %d bytes\n", headerLen)
	fmt.Printf("  Src IP: %s\n", net.IP(ipv4.SrcIP[:]).String())
	fmt.Printf("  Dst IP: %s\n", net.IP(ipv4.DstIP[:]).String())
	fmt.Printf("  Protocol: %d\n", ipv4.Protocol)

	if p.verbose {
		fmt.Printf("  TTL: %d\n", ipv4.TTL)
		totalLen := binary.BigEndian.Uint16([]byte{byte(ipv4.TotalLen >> 8), byte(ipv4.TotalLen)})
		fmt.Printf("  Total Length: %d\n", totalLen)
		fmt.Printf("  Identification: 0x%04x\n", ipv4.ID)
	}

	// 解析传输层 (如果数据足够)
	if len(payload) >= headerLen {
		switch ipv4.Protocol {
		case 6: // TCP
			p.parseTCP(payload[headerLen:])
		case 17: // UDP
			p.parseUDP(payload[headerLen:])
		case 1: // ICMP
			p.parseICMP(payload[headerLen:])
		}
	}
}

// parseIPv6 解析IPv6数据包
func (p *PacketPrinter) parseIPv6(payload []byte) {
	if len(payload) < 40 {
		fmt.Println("IPv6 header too short")
		return
	}

	// IPv6头部的简单结构
	version := payload[0] >> 4
	trafficClass := ((payload[0] & 0x0F) << 4) | (payload[1] >> 4)
	flowLabel := ((uint32(payload[1]) & 0x0F) << 16) | (uint32(payload[2]) << 8) | uint32(payload[3])
	payloadLen := binary.BigEndian.Uint16(payload[4:6])
	nextHeader := payload[6]
	hopLimit := payload[7]

	// 提取源IP和目标IP
	srcIP := net.IP(payload[8:24])
	dstIP := net.IP(payload[24:40])

	fmt.Printf("\nIPv6:\n")
	fmt.Printf("  Version: %d\n", version)
	fmt.Printf("  Src IP: %s\n", srcIP.String())
	fmt.Printf("  Dst IP: %s\n", dstIP.String())
	fmt.Printf("  Next Header: %d\n", nextHeader)

	if p.verbose {
		fmt.Printf("  Traffic Class: 0x%02x\n", trafficClass)
		fmt.Printf("  Flow Label: 0x%06x\n", flowLabel)
		fmt.Printf("  Payload Length: %d\n", payloadLen)
		fmt.Printf("  Hop Limit: %d\n", hopLimit)
	}

	// 解析传输层
	if len(payload) >= 40 {
		switch nextHeader {
		case 6: // TCP
			p.parseTCP(payload[40:])
		case 17: // UDP
			p.parseUDP(payload[40:])
		case 58: // ICMPv6
			fmt.Println("  Protocol: ICMPv6")
		}
	}
}

// parseARP 解析ARP数据包
func (p *PacketPrinter) parseARP(payload []byte) {
	if len(payload) < 28 {
		fmt.Println("ARP packet too short")
		return
	}

	hardwareType := binary.BigEndian.Uint16(payload[0:2])
	protocolType := binary.BigEndian.Uint16(payload[2:4])
	hardwareSize := payload[4]
	protocolSize := payload[5]
	operation := binary.BigEndian.Uint16(payload[6:8])

	// 提取硬件地址和协议地址
	senderMAC := net.HardwareAddr(payload[8:14])
	senderIP := net.IP(payload[14:18])
	targetMAC := net.HardwareAddr(payload[18:24])
	targetIP := net.IP(payload[24:28])

	fmt.Printf("\nARP:\n")
	fmt.Printf("  Operation: %d (%s)\n", operation, arpOperation(operation))
	fmt.Printf("  Sender MAC: %s\n", senderMAC)
	fmt.Printf("  Sender IP: %s\n", senderIP)
	fmt.Printf("  Target MAC: %s\n", targetMAC)
	fmt.Printf("  Target IP: %s\n", targetIP)

	if p.verbose {
		fmt.Printf("  Hardware Type: %d\n", hardwareType)
		fmt.Printf("  Protocol Type: 0x%04x\n", protocolType)
		fmt.Printf("  Hardware Size: %d\n", hardwareSize)
		fmt.Printf("  Protocol Size: %d\n", protocolSize)
	}
}

// arpOperation 返回ARP操作码的字符串表示
func arpOperation(opcode uint16) string {
	switch opcode {
	case 1:
		return "Request"
	case 2:
		return "Reply"
	default:
		return "Unknown"
	}
}

// parseICMP 解析ICMP数据包
func (p *PacketPrinter) parseICMP(payload []byte) {
	if len(payload) < 8 {
		fmt.Println("ICMP packet too short")
		return
	}

	icmpType := payload[0]
	icmpCode := payload[1]
	checksum := binary.BigEndian.Uint16(payload[2:4])

	fmt.Printf("\nICMP:\n")
	fmt.Printf("  Type: %d\n", icmpType)
	fmt.Printf("  Code: %d\n", icmpCode)

	if p.verbose {
		fmt.Printf("  Checksum: 0x%04x\n", checksum)

		// 根据类型显示不同的信息
		if icmpType == 8 || icmpType == 0 { // Echo请求或回复
			identifier := binary.BigEndian.Uint16(payload[4:6])
			sequence := binary.BigEndian.Uint16(payload[6:8])
			fmt.Printf("  Identifier: %d\n", identifier)
			fmt.Printf("  Sequence: %d\n", sequence)
		}
	}
}

// parseTCP 解析TCP数据包
func (p *PacketPrinter) parseTCP(payload []byte) {
	if len(payload) < 20 {
		fmt.Println("TCP header too short")
		return
	}

	// 直接读取关键字段，避免结构体对齐问题
	srcPort := binary.BigEndian.Uint16(payload[0:2])
	dstPort := binary.BigEndian.Uint16(payload[2:4])
	seqNum := binary.BigEndian.Uint32(payload[4:8])
	ackNum := binary.BigEndian.Uint32(payload[8:12])

	// 高4位是数据偏移(头部长度), 低4位是保留位
	dataOffset := (payload[12] >> 4) * 4
	flags := payload[13] // 控制位
	window := binary.BigEndian.Uint16(payload[14:16])
	checksum := binary.BigEndian.Uint16(payload[16:18])

	fmt.Printf("\nTCP:\n")
	fmt.Printf("  Src Port: %d\n", srcPort)
	fmt.Printf("  Dst Port: %d\n", dstPort)

	if p.verbose {
		fmt.Printf("  Sequence Number: %d\n", seqNum)
		fmt.Printf("  Acknowledgment Number: %d\n", ackNum)
		fmt.Printf("  Header Length: %d bytes\n", dataOffset)

		// 解析标志位
		fmt.Printf("  Flags: ")
		if (flags & 0x01) != 0 {
			fmt.Print("FIN ")
		}
		if (flags & 0x02) != 0 {
			fmt.Print("SYN ")
		}
		if (flags & 0x04) != 0 {
			fmt.Print("RST ")
		}
		if (flags & 0x08) != 0 {
			fmt.Print("PSH ")
		}
		if (flags & 0x10) != 0 {
			fmt.Print("ACK ")
		}
		if (flags & 0x20) != 0 {
			fmt.Print("URG ")
		}
		fmt.Println()

		fmt.Printf("  Window Size: %d\n", window)
		fmt.Printf("  Checksum: 0x%04x\n", checksum)

		// 通过端口号猜测应用协议
		fmt.Printf("  Application Protocol: %s\n", guessProtocol(srcPort, dstPort))
	}
}

// parseUDP 解析UDP数据包
func (p *PacketPrinter) parseUDP(payload []byte) {
	if len(payload) < 8 {
		fmt.Println("UDP header too short")
		return
	}

	// 直接读取字段，避免结构体对齐问题
	srcPort := binary.BigEndian.Uint16(payload[0:2])
	dstPort := binary.BigEndian.Uint16(payload[2:4])
	length := binary.BigEndian.Uint16(payload[4:6])
	checksum := binary.BigEndian.Uint16(payload[6:8])

	fmt.Printf("\nUDP:\n")
	fmt.Printf("  Src Port: %d\n", srcPort)
	fmt.Printf("  Dst Port: %d\n", dstPort)

	if p.verbose {
		fmt.Printf("  Length: %d\n", length)
		fmt.Printf("  Checksum: 0x%04x\n", checksum)

		// 通过端口号猜测应用协议
		fmt.Printf("  Application Protocol: %s\n", guessProtocol(srcPort, dstPort))
	}
}

// guessProtocol 根据端口号猜测应用层协议
func guessProtocol(srcPort, dstPort uint16) string {
	ports := map[uint16]string{
		20: "FTP Data", 21: "FTP Control",
		22: "SSH", 23: "Telnet",
		25: "SMTP", 53: "DNS",
		67: "DHCP Server", 68: "DHCP Client",
		80: "HTTP", 443: "HTTPS",
		3389: "RDP", 5900: "VNC",
	}

	if proto, ok := ports[srcPort]; ok {
		return proto
	}
	if proto, ok := ports[dstPort]; ok {
		return proto
	}
	return "Unknown"
}

// printHexDump 打印十六进制数据
func (p *PacketPrinter) printHexDump(data []byte) {
	const bytesPerLine = 16
	for i := 0; i < len(data); i += bytesPerLine {
		// 打印偏移量
		fmt.Printf("%04x  ", i)

		// 打印十六进制值
		end := i + bytesPerLine
		if end > len(data) {
			end = len(data)
		}

		for j := i; j < end; j++ {
			fmt.Printf("%02x ", data[j])
			if j == i+7 {
				fmt.Print(" ")
			}
		}

		// 对齐空格
		if end-i < bytesPerLine {
			spaces := (bytesPerLine - (end - i)) * 3
			if end-i <= 8 {
				spaces += 1 // 额外空格
			}
			for j := 0; j < spaces; j++ {
				fmt.Print(" ")
			}
		}

		// 打印ASCII
		fmt.Print(" |")
		for j := i; j < end; j++ {
			if data[j] >= 32 && data[j] <= 126 {
				fmt.Printf("%c", data[j])
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}
}

// printStats 打印统计信息
func (p *PacketPrinter) printStats() {
	elapsed := time.Since(p.startTime).Seconds()
	fmt.Printf("\n=== Statistics ===\n")
	fmt.Printf("Packets: %d, Bytes: %d\n", p.stats.packets, p.stats.bytes)
	fmt.Printf("Rate: %.2f pps, %.2f Mbps\n",
		float64(p.stats.packets)/elapsed,
		float64(p.stats.bytes*8)/(elapsed*1000000))
}

// min函数用于获取两个整数的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	// 解析命令行参数
	flag.StringVar(&interfaceName, "i", "", "Interface to attach XDP program to")
	flag.BoolVar(&showHex, "x", false, "Show hex dump of packets")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&debug, "d", false, "Enable debug output")
	flag.IntVar(&vmwareOffset, "offset", VMwareOffset, "VMware header offset (default: 24)")
	flag.BoolVar(&detectVMware, "auto-detect", true, "Auto-detect VMware header offset")
	flag.IntVar(&maxBytes, "max-bytes", 256, "Maximum bytes to process (default: 256)")
	flag.Parse()

	if interfaceName == "" {
		log.Fatal("Please specify an interface with -i")
	}

	// 移除内存锁限制
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 加载预编译的BPF程序
	objs := sampler_kernObjects{}
	if err := loadSampler_kernObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %v", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Fatalf("Finding interface %s: %v", interfaceName, err)
	}

	// 附加XDP程序到网络接口
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Sampler,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Attaching XDP: %v", err)
	}
	defer xdpLink.Close()

	// 创建perf reader
	rd, err := perf.NewReader(objs.Events, os.Getpagesize()*128)
	if err != nil {
		log.Fatalf("Creating perf reader: %v", err)
	}
	defer rd.Close()

	// 创建数据包打印器
	printer := NewPacketPrinter(showHex, verbose, vmwareOffset, detectVMware, maxBytes)

	// 处理信号
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	fmt.Printf("Listening on interface %s (Press Ctrl+C to stop)\n", interfaceName)
	if detectVMware {
		fmt.Println("Auto-detection of VMware header enabled")
	} else {
		fmt.Printf("Using fixed VMware header offset: %d bytes\n", vmwareOffset)
	}
	fmt.Printf("Maximum packet bytes to process: %d\n", maxBytes)

	metadataSize := binary.Size(PacketMetadata{})

	// 主循环
	for {
		select {
		case <-sig:
			fmt.Println("\nReceived signal, exiting...")
			return
		default:
			record, err := rd.Read()
			if err != nil {
				if err == perf.ErrClosed {
					return
				}
				log.Printf("Reading perf event: %v", err)
				continue
			}

			// 处理丢失的样本
			if record.LostSamples != 0 {
				log.Printf("Lost %d samples", record.LostSamples)
				continue
			}

			if debug {
				log.Printf("Received perf event of size %d bytes", len(record.RawSample))
				if len(record.RawSample) > 0 {
					log.Printf("First 32 bytes (hex): %s",
						hex.EncodeToString(record.RawSample[:min(32, len(record.RawSample))]))
				}
			}

			// 检查样本大小
			if len(record.RawSample) == metadataSize {
				// 这是元数据
				var meta PacketMetadata
				if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &meta); err != nil {
					log.Printf("Error parsing metadata: %v", err)
					continue
				}

				if debug {
					log.Printf("Parsed metadata: size=%d captured=%d proto=0x%x",
						meta.PacketSize, meta.CapturedSize, meta.Protocol)
				}

				// 等待下一个事件获取数据包内容
				nextRecord, err := rd.Read()
				if err != nil {
					log.Printf("Error reading packet data: %v", err)
					continue
				}

				if nextRecord.LostSamples != 0 {
					log.Printf("Lost samples between metadata and data")
					continue
				}

				// 处理数据包
				if int(meta.CapturedSize) > len(nextRecord.RawSample) {
					if debug {
						log.Printf("Warning: Captured size (%d) larger than actual data (%d)",
							meta.CapturedSize, len(nextRecord.RawSample))
					}
					meta.CapturedSize = uint32(len(nextRecord.RawSample))
				}

				// 打印数据包信息
				printer.PrintPacket(&meta, nextRecord.RawSample)

			} else if len(record.RawSample) > 0 {
				// 可能是直接的数据包内容，尝试处理
				if debug {
					log.Printf("Processing direct packet data of %d bytes", len(record.RawSample))
				}

				// 创建一个简单的元数据
				meta := &PacketMetadata{
					PacketSize:   uint32(len(record.RawSample)),
					CapturedSize: uint32(len(record.RawSample)),
					Protocol:     0, // 由PrintPacket函数设置
					Timestamp:    uint64(time.Now().UnixNano()),
					Flags:        0,
				}

				// 处理数据包
				printer.PrintPacket(meta, record.RawSample)
			}
		}
	}
}
