#include <linux/bpf.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <linux/string.h>
#include <stdbool.h>

#define MAX_TOPIC_ID 10
#define MAX_SUBSCRIBERS 2048
#define MAX_TOPIC_ID_CHARS 20

#define __XDP_CLONE_TX 6
#define XDP_CLONE_TX(num_copy) (((int)(num_copy) << 5) | (int)__XDP_CLONE_TX)

/* stat counter: per-CPU publish count */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} pub_counter_2 SEC(".maps");

/* topic → subscriber count */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TOPIC_ID);
    __type(key, char[MAX_TOPIC_ID_CHARS]);
    __type(value, u32);
} topic_sub_cnt SEC(".maps");

/* inner map prototype: u32 index → u64 packed subscriber (ip:port) */
struct subscriber_array_inner {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SUBSCRIBERS);
    __type(key, u32);
    __type(value, u64);
} subscriber_array_inner SEC(".maps");

typedef struct subscriber_array_inner subscriber_array_inner_t;

/* outer map: topic → inner subscriber array (indexed by copy number) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_TOPIC_ID);
    __type(key, char[MAX_TOPIC_ID_CHARS]);
    __type(value, u32);
    __array(values, subscriber_array_inner_t);
} topic_sub_array SEC(".maps");

static __always_inline __u16 compute_ip_checksum(struct iphdr *ip)
{
    __u32 csum = 0;
    __u16 *ptr = (__u16 *)ip;

#pragma clang loop unroll(disable)
    for (int i = 0; i < (sizeof(struct iphdr) >> 1); i++) {
        __u16 word = *ptr++;
        csum += word;
    }

    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);

    return ~csum;
}

static __always_inline __u16 compute_udp_checksum(struct iphdr *ip, struct udphdr *udp, void *data_end)
{
    __u32 csum = 0;
    __u32 udp_len = bpf_ntohs(udp->len);

    csum += (__u16)(ip->saddr >> 16);
    csum += (__u16)(ip->saddr & 0xFFFF);
    csum += (__u16)(ip->daddr >> 16);
    csum += (__u16)(ip->daddr & 0xFFFF);
    csum += bpf_htons(IPPROTO_UDP);
    csum += udp->len;

    __u16 *ptr = (__u16 *)udp;

#pragma unroll
    for (int i = 0; i < 1024; i++) {
        if ((void *)(ptr + 1) > data_end || (i << 1) >= udp_len)
            break;

        __u16 word = 0;
        bpf_probe_read_kernel(&word, sizeof(word), ptr);
        csum += word;
        ptr++;
    }

    if (udp_len & 1) {
        if ((void *)ptr < data_end) {
            __u8 last_byte = 0;
            bpf_probe_read_kernel(&last_byte, sizeof(last_byte), ptr);
            csum += (__u16)last_byte << 8;
        }
    }

    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);

    return ~csum;
}

static __always_inline int parse_udp_packet(struct xdp_md *ctx,
                                            void **data, void **data_end,
                                            struct ethhdr **eth,
                                            struct iphdr **ip,
                                            struct udphdr **udp,
                                            char **payload) {
    *data = (void *)(long)ctx->data;
    *data_end = (void *)(long)ctx->data_end;

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

    *payload = (char *)(*udp + 1);
    if ((void *)(*payload + 1) > *data_end)
        return -1;

    return 0;
}

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

SEC("xdp")
int xdp_broker(struct xdp_md *ctx)
{
    void *data_meta = (void *)(long)ctx->data_meta;
    void *data, *data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    char *payload;
    char topic_id[MAX_TOPIC_ID_CHARS] = {};
    __u16 dport;

    if ((void *)((__u32 *)data_meta + 1) <= (void *)(long)ctx->data) {
        /*
         * Clone copy: data_meta holds the 1-based copy index written by the
         * driver when it re-invokes XDP for each clone created by
         * XDP_CLONE_TX(n).  Copy #k is routed to subscriber at index k-1.
         */
        __u32 num_copy = *(__u32 *)data_meta;
        // bpf_printk("clone copy #%d\n", num_copy);
        if (num_copy == 0){
            // bpf_printk("invalid copy index\n");
            return XDP_DROP;
        }

        if (parse_udp_packet(ctx, &data, &data_end, &eth, &ip, &udp, &payload) < 0){
            // bpf_printk("failed to parse UDP packet\n");
            return XDP_DROP;
        }

        dport = bpf_ntohs(udp->dest);
        if (dport < 49152 || dport > 49167){
            // bpf_printk("not target port %d\n", dport);
            return XDP_DROP;
        }

        if (!starts_with(payload, "PUBLISH ", data_end)){
            // bpf_printk("not a PUBLISH packet\n");
            return XDP_DROP;
        }

        if (extract_topic_id(payload + 8, data_end, topic_id) < 0){
            // bpf_printk("failed to extract topic ID\n");
            return XDP_DROP;
        }

        void *inner_map = bpf_map_lookup_elem(&topic_sub_array, &topic_id);
        if (!inner_map){
            // bpf_printk("failed to lookup inner map for topic '%s'\n", topic_id);
            return XDP_DROP;
        }

        __u32 idx = num_copy - 1;
        __u64 *packed_ptr = bpf_map_lookup_elem(inner_map, &idx);
        if (!packed_ptr){
            // bpf_printk("failed to lookup subscriber for copy #%d\n", num_copy);
            return XDP_DROP;
        }

        __u64 packed = *packed_ptr;
        __u32 dest_ip   = packed >> 32;
        __u16 dest_port = (packed >> 16) & 0xFFFF;

        __be32 dest_ip_net   = (__be32)dest_ip;
        __be16 dest_port_net = (__be16)dest_port;

        __u8 temp_mac[ETH_ALEN];
        __builtin_memcpy(temp_mac,      eth->h_source, ETH_ALEN);
        __builtin_memcpy(eth->h_source, eth->h_dest,   ETH_ALEN);
        __builtin_memcpy(eth->h_dest,   temp_mac,      ETH_ALEN);

        ip->saddr = ip->daddr;
        ip->daddr = dest_ip_net;
        ip->check = 0;
        ip->check = compute_ip_checksum(ip);

        udp->source = udp->dest;
        udp->dest   = dest_port_net;
        udp->check  = 0;
        udp->check  = compute_udp_checksum(ip, udp,  data_end);

        return XDP_TX;
    }

    /* Original packet: if it's a PUBLISH, spawn one clone per subscriber. */
    if (parse_udp_packet(ctx, &data, &data_end, &eth, &ip, &udp, &payload) < 0){
        // bpf_printk("failed to parse UDP packet\n");
        return XDP_PASS;
    }

    dport = bpf_ntohs(udp->dest);
    if (dport < 49152 || dport > 49167){
        // bpf_printk("not target port %d\n", dport);
        return XDP_PASS;
    }

    if (!starts_with(payload, "PUBLISH ", data_end)){
        // bpf_printk("not a PUBLISH packet\n");
        return XDP_PASS;
    }
    __u32 cnt_idx = 0;
    __u32 *p_counter = bpf_map_lookup_elem(&pub_counter_2, &cnt_idx);
    if (p_counter)
        __sync_fetch_and_add(p_counter, 1);

    if (extract_topic_id(payload + 8, data_end, topic_id) < 0){
        // bpf_printk("failed to extract topic ID\n");
        return XDP_PASS;
    }

    __u32 *sub_count = bpf_map_lookup_elem(&topic_sub_cnt, &topic_id);
    if (!sub_count || *sub_count == 0){
        // bpf_printk("no subscribers for topic '%s'\n", topic_id);
        return XDP_PASS;
    }
    // bpf_printk("topic '%s' has %d subscribers\n", topic_id, *sub_count);
    return XDP_CLONE_TX(*sub_count);
}

char LICENSE[] SEC("license") = "GPL";
