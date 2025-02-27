/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// 常量定义
#define MAX_PACKET_SIZE 512
#define MAX_CPUS 16
#define ETH_HDR_SIZE 14       // 以太网头部固定大小
#define MIN_CAPTURE 34        // 至少捕获以太网+IPv4头部(14+20)
#define MAX_CAPTURE 54        // 最大尝试捕获到以太网+IPv4+TCP(14+20+20)

// 定义元数据结构
struct packet_metadata {
    __u32 packet_size;    // 原始数据包大小
    __u32 captured_size;  // 实际捕获的大小
    __u32 protocol;       // 协议类型
    __u32 flags;          // 标志位
    __u64 timestamp;      // 时间戳
} __attribute__((packed));

// 定义数据缓冲区结构
struct packet_buffer {
    __u8 data[MAX_PACKET_SIZE];
};

// 定义maps
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct packet_metadata);
    __uint(max_entries, 1);
} metadata_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct packet_buffer);
    __uint(max_entries, 1);
} packet_data_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_CPUS);
} events SEC(".maps");

SEC("xdp")
int sampler(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 确保至少有以太网头部
    if (data + ETH_HDR_SIZE > data_end)
        return XDP_PASS;

    // 获取元数据缓冲区
    __u32 zero = 0;
    struct packet_metadata *meta = bpf_map_lookup_elem(&metadata_map, &zero);
    if (!meta)
        return XDP_PASS;

    // 获取数据包缓冲区
    struct packet_buffer *buffer = bpf_map_lookup_elem(&packet_data_map, &zero);
    if (!buffer)
        return XDP_PASS;

    // 安全地计算数据包大小
    __u64 packet_size = data_end - data;
    
    // 解析以太网头部
    struct ethhdr {
        __u8 h_dest[6];
        __u8 h_source[6];
        __u16 h_proto;
    } __attribute__((packed));
    
    // 明确检查边界，确保我们可以安全访问以太网头部
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    
    // 获取以太网协议类型
    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    
    // 计算我们能捕获多少数据
    __u32 capture_size = ETH_HDR_SIZE;  // 至少捕获以太网头部
    
    // 尝试捕获更多数据，但不超过MAX_CAPTURE
    if (data + MIN_CAPTURE <= data_end) {
        // 能捕获至少以太网+IPv4头部
        capture_size = MIN_CAPTURE;
        
        // 如果有更多数据，尝试捕获更多
        if (data + MAX_CAPTURE <= data_end) {
            capture_size = MAX_CAPTURE;  // 能捕获以太网+IPv4+TCP头部
        }
    }
    
    // 填充元数据
    meta->packet_size = packet_size;
    meta->captured_size = capture_size;
    meta->protocol = eth_proto;  // 默认为以太网协议类型
    meta->timestamp = bpf_ktime_get_ns();
    meta->flags = 0;
    
    // 复制以太网头部
    buffer->data[0] = eth->h_dest[0];
    buffer->data[1] = eth->h_dest[1];
    buffer->data[2] = eth->h_dest[2];
    buffer->data[3] = eth->h_dest[3];
    buffer->data[4] = eth->h_dest[4];
    buffer->data[5] = eth->h_dest[5];
    
    buffer->data[6] = eth->h_source[0];
    buffer->data[7] = eth->h_source[1];
    buffer->data[8] = eth->h_source[2];
    buffer->data[9] = eth->h_source[3];
    buffer->data[10] = eth->h_source[4];
    buffer->data[11] = eth->h_source[5];
    
    buffer->data[12] = (__u8)(eth_proto >> 8);
    buffer->data[13] = (__u8)(eth_proto & 0xFF);
    
    // 尝试复制更多数据 - 从以太网头部之后开始
    if (data + ETH_HDR_SIZE < data_end) {
        // 复制第15个字节
        if (data + ETH_HDR_SIZE + 1 <= data_end)
            buffer->data[14] = *(__u8 *)(data + ETH_HDR_SIZE);
            
        // 复制第16个字节
        if (data + ETH_HDR_SIZE + 2 <= data_end)
            buffer->data[15] = *(__u8 *)(data + ETH_HDR_SIZE + 1);
            
        // 复制第17-20个字节
        if (data + ETH_HDR_SIZE + 6 <= data_end) {
            buffer->data[16] = *(__u8 *)(data + ETH_HDR_SIZE + 2);
            buffer->data[17] = *(__u8 *)(data + ETH_HDR_SIZE + 3);
            buffer->data[18] = *(__u8 *)(data + ETH_HDR_SIZE + 4);
            buffer->data[19] = *(__u8 *)(data + ETH_HDR_SIZE + 5);
        }
        
        // 继续复制更多数据...
        // 这里使用静态展开而不是循环，以确保通过验证器
        // 复制IPv4头部的关键字段(协议、源IP、目标IP)
        if (eth_proto == 0x0800) {
            // 协议字段(第10个字节)
            if (data + ETH_HDR_SIZE + 10 <= data_end) {
                buffer->data[ETH_HDR_SIZE + 9] = *(__u8 *)(data + ETH_HDR_SIZE + 9);
                meta->protocol = *(__u8 *)(data + ETH_HDR_SIZE + 9);  // IP协议
            }
            
            // 源IP地址(第13-16个字节)
            if (data + ETH_HDR_SIZE + 16 <= data_end) {
                buffer->data[ETH_HDR_SIZE + 12] = *(__u8 *)(data + ETH_HDR_SIZE + 12);
                buffer->data[ETH_HDR_SIZE + 13] = *(__u8 *)(data + ETH_HDR_SIZE + 13);
                buffer->data[ETH_HDR_SIZE + 14] = *(__u8 *)(data + ETH_HDR_SIZE + 14);
                buffer->data[ETH_HDR_SIZE + 15] = *(__u8 *)(data + ETH_HDR_SIZE + 15);
            }
            
            // 目标IP地址(第17-20个字节)
            if (data + ETH_HDR_SIZE + 20 <= data_end) {
                buffer->data[ETH_HDR_SIZE + 16] = *(__u8 *)(data + ETH_HDR_SIZE + 16);
                buffer->data[ETH_HDR_SIZE + 17] = *(__u8 *)(data + ETH_HDR_SIZE + 17);
                buffer->data[ETH_HDR_SIZE + 18] = *(__u8 *)(data + ETH_HDR_SIZE + 18);
                buffer->data[ETH_HDR_SIZE + 19] = *(__u8 *)(data + ETH_HDR_SIZE + 19);
            }
            
            // 继续复制更多数据，如果是TCP或UDP协议
            if (data + ETH_HDR_SIZE + 10 <= data_end) {
                __u8 ip_proto = *(__u8 *)(data + ETH_HDR_SIZE + 9);
                if (ip_proto == 6 || ip_proto == 17) {  // TCP或UDP
                    // 复制端口号
                    if (data + ETH_HDR_SIZE + 24 <= data_end) {
                        buffer->data[ETH_HDR_SIZE + 20] = *(__u8 *)(data + ETH_HDR_SIZE + 20);
                        buffer->data[ETH_HDR_SIZE + 21] = *(__u8 *)(data + ETH_HDR_SIZE + 21);
                        buffer->data[ETH_HDR_SIZE + 22] = *(__u8 *)(data + ETH_HDR_SIZE + 22);
                        buffer->data[ETH_HDR_SIZE + 23] = *(__u8 *)(data + ETH_HDR_SIZE + 23);
                    }
                }
            }
        }
    }
    
    // 发送元数据
    __u32 meta_size = sizeof(struct packet_metadata);
    int ret = bpf_perf_event_output(ctx, &events, 
                                  BPF_F_CURRENT_CPU | ((__u64)meta_size << 32),
                                  meta, meta_size);
    if (ret < 0)
        return XDP_PASS;

    // 发送数据包内容
    __u32 data_size = capture_size;
    if (data_size > MAX_CAPTURE)
        data_size = MAX_CAPTURE;  // 确保不超过最大值
        
    bpf_perf_event_output(ctx, &events, 
                         BPF_F_CURRENT_CPU | ((__u64)data_size << 32), 
                         buffer->data, data_size);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";