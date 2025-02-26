/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

#define MAX_PACKET_SIZE 256
#define MAX_CPUS 16

// 定义元数据结构 - 确保与Go代码匹配
struct packet_metadata {
    __u32 packet_size;
    __u32 captured_size;
    __u32 protocol;
    __u32 flags;
    __u64 timestamp;
} __attribute__((packed)); // 确保紧凑布局，没有填充

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

// 辅助函数：发送数据到perf buffer
static __always_inline int
send_to_perf(struct xdp_md *ctx, void *map, void *data, __u32 size)
{
    __u64 flags = BPF_F_CURRENT_CPU;
    flags |= (__u64)size << 32;
    return bpf_perf_event_output(ctx, map, flags, data, size);
}

SEC("xdp")
int sampler(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 基本边界检查
    if (data >= data_end)
        return XDP_PASS;

    // 计算数据包大小
    __u64 packet_size = data_end - data;
    __u32 safe_packet_size = packet_size > 0xffffffff ? 0xffffffff : (__u32)packet_size;
    __u32 sample_size = safe_packet_size;
    if (sample_size > MAX_PACKET_SIZE)
        sample_size = MAX_PACKET_SIZE;

    // 确保至少能访问以太网头部
    if (data + 14 > data_end)
        return XDP_PASS;

    // 获取元数据缓冲区
    __u32 zero = 0;
    struct packet_metadata *meta = bpf_map_lookup_elem(&metadata_map, &zero);
    if (!meta)
        return XDP_PASS;

    // 获取协议类型
    struct ethhdr *eth = data;
    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    // 填充元数据
    meta->packet_size = safe_packet_size;
    meta->captured_size = sample_size;
    meta->timestamp = bpf_ktime_get_ns();
    meta->protocol = eth_proto;
    meta->flags = 0;

    // 获取数据包缓冲区
    struct packet_buffer *buffer = bpf_map_lookup_elem(&packet_data_map, &zero);
    if (!buffer)
        return XDP_PASS;

    // 复制以太网头部 (一定能访问到，前面已经检查)
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
    
    buffer->data[12] = (eth_proto >> 8) & 0xFF;
    buffer->data[13] = eth_proto & 0xFF;

    // 发送元数据 - 使用明确的大小，确保Go端匹配正确
    int ret = send_to_perf(ctx, &events, meta, sizeof(struct packet_metadata));
    if (ret < 0)
        return XDP_PASS;

    // 发送数据包内容
    ret = send_to_perf(ctx, &events, buffer->data, 14);  // 只发送以太网头
    if (ret < 0)
        return XDP_PASS;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";