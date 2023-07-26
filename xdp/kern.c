#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define XDP_ACTION_MAX (XDP_REDIRECT + 1)

struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct datarec));
    __uint(max_entries, XDP_ACTION_MAX);
} xdp_stats_map SEC(".maps");

static __always_inline __u32 xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
{
    if (action >= XDP_ACTION_MAX) {
        return XDP_ABORTED;
    }

    struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
    if (!rec) {
        return XDP_ABORTED;
    }

    rec->rx_packets += 1;
    rec->rx_bytes += (ctx->data_end - ctx->data);

    return action;
}

SEC("xdp.pass")
int xdp_pass(struct xdp_md *ctx)
{
    return xdp_stats_record_action(ctx, XDP_PASS);
}

SEC("xdp.drop")
int xdp_drop(struct xdp_md *ctx)
{
    return xdp_stats_record_action(ctx, XDP_DROP);
}

SEC("xdp.aborted")
int xdp_aborted(struct xdp_md *ctx)
{
    return xdp_stats_record_action(ctx, XDP_ABORTED);
}

char _license[] SEC("license") = "GPL";
