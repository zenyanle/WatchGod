// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_xdp.h>

/* Define XDP actions if not defined */
#ifndef XDP_ABORTED
#define XDP_ABORTED       0
#endif

#ifndef XDP_DROP
#define XDP_DROP         1
#endif

#ifndef XDP_PASS
#define XDP_PASS         2
#endif

#ifndef XDP_TX
#define XDP_TX           3
#endif

#ifndef XDP_REDIRECT
#define XDP_REDIRECT     4
#endif

/* Define max actions */
#define XDP_MAX_ACTIONS  5

#define MAX_CPUS 32
#define MAX_SAMPLE_SIZE 65535

/* Define map types using BTF-enabled CO-RE format */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct counters);
    __uint(max_entries, XDP_MAX_ACTIONS);
} action_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} sample_rate SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} packet_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_CPUS);
} samples SEC(".maps");

struct perf_metadata {
    __u16 cookie;
    __u16 length;
} __attribute__((packed));

struct counters {
    __u64 packets;
    __u64 bytes;
};

/* Helper function to update stats */
static __always_inline __u32 
update_action_stats(struct xdp_md *ctx, __u32 action)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u32 length = (__u32)(data_end - data);

    struct counters *counters = bpf_map_lookup_elem(&action_counters, &action);
    if (!counters)
        return XDP_ABORTED;

    counters->packets++;
    counters->bytes += length;

    return action;
}

SEC("xdp")
int sampler_fn(struct xdp_md *ctx)
{
    __u32 action = XDP_PASS;
    __u32 key = 0;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    if (data >= data_end)
        return XDP_ABORTED;

    __u32 length = (__u32)(data_end - data);

    /* Get sampling rate */
    __u32 *current_sample_rate = bpf_map_lookup_elem(&sample_rate, &key);
    if (!current_sample_rate)
        goto out;

    /* Get and update packet counter */
    __u32 *current_packet_count = bpf_map_lookup_elem(&packet_count, &key);
    if (!current_packet_count)
        goto out;

    (*current_packet_count)++;

    /* Check if we should sample this packet */
    if (*current_sample_rate > 0 && (*current_packet_count % *current_sample_rate) == 0) {
        __u64 flags = BPF_F_CURRENT_CPU;
        
        struct perf_metadata metadata = {
            .cookie = 0xcafe,
            .length = length,
        };

        /* Cap sample size */
        __u16 sample_size = length > MAX_SAMPLE_SIZE ? MAX_SAMPLE_SIZE : length;
        flags |= (__u64)sample_size << 32;

        int ret = bpf_perf_event_output(ctx, &samples, flags, 
                                      &metadata, sizeof(metadata));
        if (ret)
            bpf_printk("Failed to write sampled packet: err=%d\n", ret);
    }

out:
    return update_action_stats(ctx, action);
}

char LICENSE[] SEC("license") = "GPL";