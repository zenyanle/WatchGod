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
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// 常量定义
const (
	MaxPacketSize = 256 // 与内核程序保持一致
)

// 命令行参数
var (
	interfaceName string
	showHex       bool
	verbose       bool
	debug         bool // 添加调试选项
)

// PacketMetadata 对应内核传来的元数据
type PacketMetadata struct {
	PacketSize   uint32
	CapturedSize uint32
	Protocol     uint32
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
	Version  uint8
	IHL      uint8
	TOS      uint8
	TotalLen uint16
	ID       uint16
	Flags    uint16
	TTL      uint8
	Protocol uint8
	Checksum uint16
	SrcIP    [4]byte
	DstIP    [4]byte
}

// PacketPrinter 数据包打印器
type PacketPrinter struct {
	showHex bool
	verbose bool
	stats   struct {
		packets uint64
		bytes   uint64
	}
	startTime time.Time
}

// NewPacketPrinter 创建新的数据包打印器
func NewPacketPrinter(showHex, verbose bool) *PacketPrinter {
	return &PacketPrinter{
		showHex:   showHex,
		verbose:   verbose,
		startTime: time.Now(),
	}
}

// PrintPacket 打印数据包内容
func (p *PacketPrinter) PrintPacket(meta *PacketMetadata, payload []byte) {
	// 更新统计信息
	p.stats.packets++
	p.stats.bytes += uint64(meta.PacketSize)

	// 打印数据包信息
	fmt.Printf("\n=== Packet Captured at %s ===\n",
		time.Unix(0, int64(meta.Timestamp)).Format("2006-01-02 15:04:05.000000"))
	fmt.Printf("Original Size: %d bytes, Captured: %d bytes\n",
		meta.PacketSize, meta.CapturedSize)

	// 解析以太网头部
	if len(payload) < 14 {
		fmt.Println("Packet too short for Ethernet header")
		return
	}

	eth := &EthernetHeader{}
	reader := bytes.NewReader(payload)
	if err := binary.Read(reader, binary.BigEndian, eth); err != nil {
		fmt.Printf("Error reading Ethernet header: %v\n", err)
		return
	}

	fmt.Printf("\nEthernet:\n")
	fmt.Printf("  Src MAC: %s\n", net.HardwareAddr(eth.SrcMAC[:]))
	fmt.Printf("  Dst MAC: %s\n", net.HardwareAddr(eth.DstMAC[:]))
	fmt.Printf("  Type: 0x%04x\n", eth.EtherType)

	// 根据EtherType解析上层协议
	if eth.EtherType == 0x0800 && len(payload) >= 34 { // 确保有足够数据解析IPv4
		p.parseIPv4(payload[14:])
	}

	// 显示十六进制数据
	if p.showHex {
		fmt.Println("\nHex dump:")
		p.printHexDump(payload)
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
		return
	}

	ipv4 := &IPv4Header{}
	reader := bytes.NewReader(payload)
	if err := binary.Read(reader, binary.BigEndian, ipv4); err != nil {
		return
	}

	fmt.Printf("\nIPv4:\n")
	fmt.Printf("  Src IP: %s\n", net.IP(ipv4.SrcIP[:]))
	fmt.Printf("  Dst IP: %s\n", net.IP(ipv4.DstIP[:]))
	fmt.Printf("  Protocol: %d\n", ipv4.Protocol)

	if p.verbose {
		fmt.Printf("  TTL: %d\n", ipv4.TTL)
		fmt.Printf("  Total Length: %d\n", ipv4.TotalLen)
	}

	// 解析传输层
	headerLen := int(ipv4.IHL) * 4
	if len(payload) >= headerLen {
		switch ipv4.Protocol {
		case 6: // TCP
			p.parseTCP(payload[headerLen:])
		case 17: // UDP
			p.parseUDP(payload[headerLen:])
		}
	}
}

// parseTCP 解析TCP数据包
func (p *PacketPrinter) parseTCP(payload []byte) {
	if len(payload) < 20 {
		return
	}
	srcPort := binary.BigEndian.Uint16(payload[0:2])
	dstPort := binary.BigEndian.Uint16(payload[2:4])
	fmt.Printf("\nTCP:\n")
	fmt.Printf("  Src Port: %d\n", srcPort)
	fmt.Printf("  Dst Port: %d\n", dstPort)
}

// parseUDP 解析UDP数据包
func (p *PacketPrinter) parseUDP(payload []byte) {
	if len(payload) < 8 {
		return
	}
	srcPort := binary.BigEndian.Uint16(payload[0:2])
	dstPort := binary.BigEndian.Uint16(payload[2:4])
	fmt.Printf("\nUDP:\n")
	fmt.Printf("  Src Port: %d\n", srcPort)
	fmt.Printf("  Dst Port: %d\n", dstPort)
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

func main() {
	// 解析命令行参数
	flag.StringVar(&interfaceName, "i", "", "Interface to attach XDP program to")
	flag.BoolVar(&showHex, "x", false, "Show hex dump of packets")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&debug, "d", false, "Enable debug output")
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
	printer := NewPacketPrinter(showHex, verbose)

	// 处理信号
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	fmt.Printf("Listening on interface %s (Press Ctrl+C to stop)\n", interfaceName)

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

			// 详细输出事件大小和原始数据（前几个字节）
			if debug {
				log.Printf("Received perf event of size %d bytes", len(record.RawSample))
				if len(record.RawSample) > 0 {
					log.Printf("First 32 bytes (hex): %s",
						hex.EncodeToString(record.RawSample[:min(32, len(record.RawSample))]))
				}
			}

			// 尝试推断事件类型
			// 收到的事件大小是28字节，这可能是元数据(24字节)带有一些额外信息
			// 或者可能是带有一些额外头信息的14字节以太网头部
			switch len(record.RawSample) {
			case metadataSize:
				// 正好是元数据大小
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

				printer.PrintPacket(&meta, nextRecord.RawSample)

			case 28: // 特殊处理28字节的情况
				// 尝试解析为元数据+前4字节的数据包
				var meta PacketMetadata
				if err := binary.Read(bytes.NewReader(record.RawSample[:metadataSize]), binary.LittleEndian, &meta); err != nil {
					log.Printf("Error parsing potential metadata: %v", err)
					continue
				}

				// 判断解析出的元数据是否有意义
				if meta.PacketSize > 0 && meta.PacketSize < 65536 &&
					meta.CapturedSize > 0 && meta.CapturedSize <= meta.PacketSize {

					if debug {
						log.Printf("Interpreted as metadata: size=%d captured=%d proto=0x%x",
							meta.PacketSize, meta.CapturedSize, meta.Protocol)
					}

					// 提取数据部分（后4字节）
					initialData := record.RawSample[metadataSize:]

					// 判断是否需要读取更多数据
					if int(meta.CapturedSize) > len(initialData) {
						// 需要读取更多数据
						nextRecord, err := rd.Read()
						if err != nil {
							log.Printf("Error reading remaining packet data: %v", err)
							continue
						}

						// 组合两部分数据
						fullData := make([]byte, len(initialData)+len(nextRecord.RawSample))
						copy(fullData, initialData)
						copy(fullData[len(initialData):], nextRecord.RawSample)

						// 确保不超过捕获大小
						if len(fullData) > int(meta.CapturedSize) {
							fullData = fullData[:meta.CapturedSize]
						}

						printer.PrintPacket(&meta, fullData)
					} else {
						// 数据已经足够
						printer.PrintPacket(&meta, initialData[:meta.CapturedSize])
					}
				} else {
					// 不像是合法的元数据，可能是其他数据
					log.Printf("Raw event data (28 bytes): %s",
						hex.EncodeToString(record.RawSample))
				}

			default:
				// 对于其他大小的事件，尝试看是否可以提取有效数据
				if len(record.RawSample) >= 14 { // 至少有以太网头部
					// 尝试作为纯数据包处理
					eth := &EthernetHeader{}
					if err := binary.Read(bytes.NewReader(record.RawSample[:14]), binary.BigEndian, eth); err == nil {
						// 看起来像是以太网包
						meta := &PacketMetadata{
							PacketSize:   uint32(len(record.RawSample)),
							CapturedSize: uint32(len(record.RawSample)),
							Protocol:     uint32(eth.EtherType),
							Timestamp:    uint64(time.Now().UnixNano()),
						}

						printer.PrintPacket(meta, record.RawSample)
					} else {
						log.Printf("Unrecognized event format: %d bytes", len(record.RawSample))
					}
				} else {
					log.Printf("Unexpected event size: %d bytes", len(record.RawSample))
				}
			}
		}
	}
}

// min函数用于获取两个整数的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
