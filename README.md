# WatchGod - 网络数据包捕获与分析工具

## 概述

WatchGod是一个基于eBPF/XDP的网络数据包捕获和分析工具，能够实时监控网络接口、捕获数据包、解析各层协议，并以可读格式呈现。特别适合在VMware等虚拟化环境中使用。

## 功能特点

- 使用eBPF/XDP技术，高效且低开销
- 支持以太网、IPv4、IPv6、ARP、TCP、UDP、ICMP等协议解析
- 自动检测VMware环境下的帧偏移
- 提供可读性强的协议解析和十六进制转储
- 统计数据包吞吐量和比特率

## 文件结构

- `main.go` - 主程序，处理命令行参数和eBPF事件循环
- `types.go` - 定义数据结构和常量
- `packet_printer.go` - 数据包打印和格式化
- `parsers.go` - 各种网络协议的解析逻辑
- `utils.go` - 通用辅助函数
- `internal/sampler_kern.c` - eBPF/XDP内核程序
- `internal/sampler_kern_*.go` - 生成的eBPF/XDP对象文件

## 使用方法

```bash
# 编译程序
go build

# 运行程序
./watchgod -i eth0 -x -v

# 命令行参数
-i string   指定监听的网络接口
-x          显示十六进制数据转储
-v          显示详细输出
-d          启用调试信息
-offset int 指定VMware头部偏移(默认:24)
-auto-detect 自动检测VMware头部偏移(默认:开启)
-max-bytes int 限制处理的最大字节数(默认:512)