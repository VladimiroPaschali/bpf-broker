#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/string.h>

#include "bmc_common.h"

#define MAX_TOPIC_ID 10
#define MAX_SUBSCRIBERS 1024
#define MAX_TOPIC_ID_CHARS 20


struct callback_ctx {
    struct __sk_buff *skb;
};

/* program maps */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, BMC_PROG_TC_MAX);
} map_progs_tc SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} publish_counter SEC(".maps");

// Inner map: subscriber IP -> dummy (u8)
struct subscriber_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u64);
    __type(value, u32);
} subscriber_map SEC(".maps");

typedef struct subscriber_map subscriber_map_t;

// Outer map: topic ID -> inner map of subscribers
struct topic_subscriber_maps {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_TOPIC_ID);
    __type(key, char[MAX_TOPIC_ID_CHARS]);
    __array(values, subscriber_map_t);
} topic_subscribe SEC(".maps");

static __inline int starts_with(const char *p, const char *prefix, void *end) {
    int i = 0;
    for (; prefix[i]; i++) {
        if ((void *)&p[i] >= end || p[i] != prefix[i])
            return 0;
    }
    return 1;
}

static __inline int extract_topic_id(char *s, void *end, char *out_id) {
#pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_TOPIC_ID_CHARS; i++) {
        if ((void *)(s + i + 1) > end)
            return -1;
        char c;
        bpf_probe_read_kernel(&c, sizeof(c), s + i);
        if (c == ' ' || c == '\0' || c == '\n') {
            out_id[i] = '\0';
            return 0;
        }
        out_id[i] = c;
    }
    out_id[MAX_TOPIC_ID_CHARS - 1] = '\0';
    return 0;
}

static __always_inline int refresh_headers(struct __sk_buff *skb,
                                           void **data, void **data_end,
                                           struct ethhdr **eth,
                                           struct iphdr **ip,
                                           struct udphdr **udp) {
    *data = (void *)(long)skb->data;
    *data_end = (void *)(long)skb->data_end;

    *eth = *data;
    if ((void *)(*eth + 1) > *data_end)
        return -1;

    if ((*eth)->h_proto != __constant_htons(ETH_P_IP))
        return -1;

    *ip = (void *)(*eth + 1);
    if ((void *)(*ip + 1) > *data_end)
        return -1;

    if ((*ip)->protocol != IPPROTO_UDP)
        return -1;

    *udp = (void *)(*ip + 1);
    if ((void *)(*udp + 1) > *data_end)
        return -1;

    return 0;
}

static __inline void bpf_printk_ip(__be32 ip, __be16 port, const char *prefix) {
    __u8 a = ip & 0xFF;
    __u8 b = (ip >> 8) & 0xFF;
    __u8 c = (ip >> 16) & 0xFF;
    __u8 d = (ip >> 24) & 0xFF;
    bpf_printk("%s %d.%d.%d.%d:%d\n", prefix, a, b, c, d, bpf_ntohs(port));
}

static long callback_fn(struct bpf_map *map, const void *key, void *value, void *ctx_void)
{
    struct callback_ctx *ctx = (struct callback_ctx *)ctx_void;
    struct __sk_buff *skb = ctx->skb;
    __u64 packed = *(__u64 *)key;

    __u32 dest_ip = packed >> 32;
    __u16 dest_port = (packed >> 16) & 0xFFFF;

    __be32 dest_ip_net = (__be32)dest_ip;
    __be16 dest_port_net = (__be16)dest_port;

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;

    if (refresh_headers(skb, &data, &data_end, &eth, &ip, &udp) < 0)
        return TC_ACT_OK;

    __be32 old_daddr = ip->daddr;
    __be16 old_port = udp->dest;

    ip->daddr = dest_ip_net;
    
    if (bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                    old_daddr, ip->daddr, sizeof(__be32)) < 0) 
        return TC_ACT_OK;

    if (refresh_headers(skb, &data, &data_end, &eth, &ip, &udp) < 0)
        return TC_ACT_OK;

    if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check),
                        old_daddr, ip->daddr, sizeof(__be32) | BPF_F_PSEUDO_HDR) < 0)
        return TC_ACT_OK;

    if (refresh_headers(skb, &data, &data_end, &eth, &ip, &udp) < 0)
        return TC_ACT_OK;

    udp->dest = dest_port_net;
    if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check),
                        old_port, udp->dest, sizeof(__be16) | BPF_F_PSEUDO_HDR) < 0)
        return TC_ACT_OK;

    if (refresh_headers(skb, &data, &data_end, &eth, &ip, &udp) < 0)
        return TC_ACT_OK;

    // bpf_printk_ip(ip->daddr, udp->dest, "Callback: Cloning packet to");
    bpf_clone_redirect(ctx->skb, ctx->skb->ifindex, 0);
    return 0;
}


SEC("tc")
int tc_ingress_broker(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;

    if (bpf_skb_pull_data(skb, skb->len) < 0)
        return TC_ACT_OK;

    if (refresh_headers(skb, &data, &data_end, &eth, &ip, &udp) < 0)
        return TC_ACT_OK;

    if (ntohs(udp->dest) != 11211)
        return TC_ACT_OK;

    char *payload = (void *)udp + sizeof(*udp);

    if (starts_with(payload, "PUBLISH ", data_end)) {
        __u32 idx = 0;
        __u32 *counter = bpf_map_lookup_elem(&publish_counter, &idx);
        if (counter) {
            __sync_fetch_and_add(counter, 1);
        }

        char topic_id[MAX_TOPIC_ID_CHARS] = {};
        if (extract_topic_id(payload + 8, data_end, topic_id) < 0)
            return TC_ACT_OK;

        void *inner_map = bpf_map_lookup_elem(&topic_subscribe, &topic_id);
        if (!inner_map)
            return TC_ACT_OK;

        // bpf_printk("PUBLISH find topic '%s'", topic_id);

        __u8 temp_mac[ETH_ALEN];
        __builtin_memcpy(temp_mac, eth->h_source, ETH_ALEN);
        __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
        __builtin_memcpy(eth->h_dest, temp_mac, ETH_ALEN);

        __be32 temp_ip = ip->saddr;
        ip->saddr = ip->daddr;
        // ip->daddr = temp_ip;

        if (bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                        temp_ip, ip->saddr, sizeof(__be32)) < 0)
            return TC_ACT_OK;

        if (refresh_headers(skb, &data, &data_end, &eth, &ip, &udp) < 0)
            return TC_ACT_OK;

        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check),
                        temp_ip, ip->saddr, sizeof(__be32) | BPF_F_PSEUDO_HDR) < 0)
            return TC_ACT_OK;

        if (refresh_headers(skb, &data, &data_end, &eth, &ip, &udp) < 0)
            return TC_ACT_OK;

        __be16 temp_port = udp->source;
        udp->source = udp->dest;
        // udp->dest = temp_port;

        if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check),
                        temp_port, udp->source, sizeof(__be16) | BPF_F_PSEUDO_HDR) < 0)
            return TC_ACT_OK;
        
        // bpf_clone_redirect(skb, skb->ifindex, 0);

        struct callback_ctx ctx = {
            .skb = skb,
        };

        long (*cb_p)(struct bpf_map *, const void *, void *, void *) = &callback_fn;

        bpf_for_each_map_elem(inner_map, cb_p, &ctx, 0);

        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
