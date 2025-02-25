package main

import (
	"bytes"
	"encoding/binary"
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
)

// 命令行参数
var (
	interfaceName string
	sampleRate    uint
)

func init() {
	// 解析命令行参数
	flag.StringVar(&interfaceName, "interface", "", "网络接口名称")
	flag.UintVar(&sampleRate, "rate", 100, "采样率 (每N个包采样一个)")
	flag.Parse()

	if interfaceName == "" {
		log.Fatal("请指定网络接口名称 (-interface)")
	}
}

func main() {

	// 加载预编译的BPF程序
	var objs sampler_kernObjects
	if err := loadSampler_kernObjects(&objs, nil); err != nil {
		log.Fatalf("加载对象错误: %v", err)
	}
	defer objs.Close()

	// 设置采样率
	key := uint32(0)
	rate := uint32(sampleRate)
	if err := objs.SampleRate.Put(&key, &rate); err != nil {
		log.Fatalf("设置采样率错误: %v", err)
	}

	iface, err := net.InterfaceByName(interfaceName)

	// 将XDP程序附加到网络接口
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.SamplerFn,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("附加到接口错误: %v", err)
	}
	defer xdpLink.Close()

	// 设置perf reader
	rd, err := perf.NewReader(objs.Samples, os.Getpagesize())
	if err != nil {
		log.Fatalf("创建perf reader错误: %v", err)
	}
	defer rd.Close()

	// 处理信号以优雅退出
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// 创建一个计时器用于定期打印统计信息
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	fmt.Printf("采样程序已启动在接口 %s 上 (采样率: 每%d个包采样一个)\n", interfaceName, sampleRate)
	fmt.Println("按Ctrl+C退出")

	// 主循环
	for {
		select {
		case <-sig:
			fmt.Println("\n接收到退出信号，正在清理...")
			return
		case <-ticker.C:
			// 打印统计信息
			printStats(&objs)
		default:
			// 读取perf事件
			record, err := rd.Read()
			if err != nil {
				if err == perf.ErrClosed {
					return
				}
				log.Printf("读取错误: %v", err)
				continue
			}

			// 处理丢失的样本
			if record.LostSamples != 0 {
				log.Printf("丢失 %d 个样本\n", record.LostSamples)
				continue
			}

			// 解析和打印采样数据
			var metadata struct {
				Cookie uint16
				Length uint16
			}

			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &metadata); err != nil {
				log.Printf("解析元数据错误: %v", err)
				continue
			}

			// 打印采样信息
			fmt.Printf("采样数据包: 长度=%d 字节 Cookie=0x%x\n",
				metadata.Length, metadata.Cookie)
		}
	}
}

// printStats 打印XDP动作的统计信息
func printStats(objs *sampler_kernObjects) {
	var (
		key     uint32
		counter sampler_kernCounters
	)

	// 获取和打印数据包计数
	var packetCount uint32
	if err := objs.PacketCount.Lookup(&key, &packetCount); err == nil {
		fmt.Printf("\n总处理数据包: %d\n", packetCount)
	}

	// 获取和打印计数器
	if err := objs.ActionCounters.Lookup(&key, &counter); err == nil {
		fmt.Printf("通过的数据包: %d (总字节: %d)\n",
			counter.Packets, counter.Bytes)
	}
}
