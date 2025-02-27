/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

#define MAX_PACKET_SIZE 256
#define MAX_CPUS 16
#define ETH_HDR_SIZE 14      // 以太网头部固定大小
#define CAPTURE_SIZE 26      // 我们想捕获的固定字节数

// 定义元数据结构
struct packet_metadata {
    __u32 packet_size;
    __u32 captured_size;
    __u32 protocol;
    __u32 flags;
    __u64 timestamp;
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
    
    // 基本边界检查
    if (data + ETH_HDR_SIZE > data_end)
        return XDP_PASS;

    // 计算数据包大小 - 使用无符号类型
    __u64 packet_size = data_end - data;
    __u32 safe_packet_size = packet_size;
    
    // 获取元数据缓冲区
    __u32 zero = 0;
    struct packet_metadata *meta = bpf_map_lookup_elem(&metadata_map, &zero);
    if (!meta)
        return XDP_PASS;

    // 获取数据包缓冲区
    struct packet_buffer *buffer = bpf_map_lookup_elem(&packet_data_map, &zero);
    if (!buffer)
        return XDP_PASS;

    // 复制以太网头部 - 直接通过结构体访问
    struct ethhdr *eth = data;
    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    
    // 填充元数据 - 使用常量大小
    meta->packet_size = safe_packet_size;
    meta->captured_size = ETH_HDR_SIZE;  // 先设为最小值
    meta->protocol = eth_proto;
    meta->timestamp = bpf_ktime_get_ns();
    meta->flags = 0;
    
    // 复制以太网头部 - 直接复制MAC地址
    __builtin_memcpy(buffer->data, eth->h_dest, 6);
    __builtin_memcpy(buffer->data + 6, eth->h_source, 6);
    buffer->data[12] = eth_proto >> 8;
    buffer->data[13] = eth_proto & 0xFF;
    
    // 尝试复制额外的12字节 - 如果有足够数据
    if (data + CAPTURE_SIZE <= data_end) {
        // 有足够数据复制26字节 (14+12)
        __builtin_memcpy(buffer->data + 14, data + 14, 12);
        meta->captured_size = CAPTURE_SIZE;  // 26字节
    }
    
    // 发送元数据 - 使用固定大小
    __u32 meta_size = sizeof(struct packet_metadata);
    int ret = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU | ((__u64)meta_size << 32),
                                   meta, meta_size);
    if (ret < 0)
        return XDP_PASS;

    // 发送数据包内容 - 使用固定大小，避免可变大小
    __u32 data_size = meta->captured_size;
    if (data_size > CAPTURE_SIZE)  // 添加明确的上限
        data_size = CAPTURE_SIZE;

    ret = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU | ((__u64)data_size << 32), 
                               buffer->data, data_size);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";