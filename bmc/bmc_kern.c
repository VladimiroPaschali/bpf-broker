#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/string.h>

#include "bmc_common.h"

#define MAX_TOPIC_ID 10
#define MAX_SUBSCRIBERS 256
#define MAX_TOPIC_ID_CHARS 20

#ifndef BPF_FUNC_map_get_next_key
#define BPF_FUNC_map_get_next_key 5
#endif

static int (*bpf_map_get_next_key)(void *map, const void *key, void *next_key) = (void *) BPF_FUNC_map_get_next_key;

/* program maps */

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, BMC_PROG_TC_MAX);
} map_progs_tc SEC(".maps");


// Inner map: subscriber IP -> dummy (u8)
struct subscriber_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, u32);
} subscriber_map SEC(".maps");

typedef struct subscriber_map subscriber_map_t;

// Outer map: topic ID -> inner map of subscribers
struct topic_subscriber_maps {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_TOPIC_ID);
    __type(key, char[MAX_TOPIC_ID_CHARS]);                       // topic ID
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

// Helper: Parse numeric topic ID
static __inline int parse_topic_id(char *s, void *end, __u16 *out_id) {
    int val = 0;
    int digits = 0;

#pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_TOPIC_ID_CHARS; i++) {
        if ((void *)(s + i + 1) > end)
            break;

        char c;
        bpf_probe_read_kernel(&c, sizeof(c), s + i); // safe access

        if (c < '0' || c > '9')
            break;

        val = val * 10 + (c - '0');
        digits++;
    }

    if (digits == 0 || digits >= MAX_TOPIC_ID_CHARS)
        return -1;

    *out_id = (__u16)val;
    return 0;
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


SEC("tc")
int tc_ingress_broker(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    __be16 dport;

    if (bpf_skb_pull_data(skb, skb->len) < 0)
        return TC_ACT_OK;

    data_end = (void *)(long)skb->data_end;
    data = (void *)(long)skb->data;
    eth = data;

    if ((void *)eth + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    ip = (void *)eth + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    udp = (void *)ip + sizeof(*ip);
    if ((void *)udp + sizeof(*udp) > data_end)
        return TC_ACT_OK;

    dport = udp->dest;

    if (ntohs(dport) != 11211)
        return TC_ACT_OK;

    char *payload = (void *)udp + sizeof(*udp);

    // -------- Handle SUBSCRIBE --------
    if (starts_with(payload, "SUBSCRIBE ", data_end)) {
       char topic_id[MAX_TOPIC_ID_CHARS] = {};
        if (extract_topic_id(payload + 10, data_end, topic_id) < 0)
            return TC_ACT_OK;

        __u32 subscriber_ip = ip->saddr;
        __u8 dummy = 1;

        void *inner_map = bpf_map_lookup_elem(&topic_subscribe, &topic_id);
        if (!inner_map)
            return TC_ACT_OK;

        bpf_map_update_elem(inner_map, &subscriber_ip, &dummy, BPF_ANY);
        bpf_printk("SUBSCRIBE topic %d ← IP 0x%x\n", topic_id, subscriber_ip);
        return TC_ACT_OK;
    }

    // -------- Handle PUBLISH --------
    if (starts_with(payload, "PUBLISH ", data_end)) {
        char topic_id[MAX_TOPIC_ID_CHARS] = {};
        if (extract_topic_id(payload + 8, data_end, topic_id) < 0)
            return TC_ACT_OK;

        void *inner_map = bpf_map_lookup_elem(&topic_subscribe, &topic_id);
        if (!inner_map)
            return TC_ACT_OK;

        struct ethhdr *eth = data;
        struct iphdr *ip = (void *)(eth + 1);
        struct udphdr *udp = (void *)(ip + 1);

        __be32 orig_saddr = ip->saddr;
        __be16 orig_sport = udp->source;

        __u32 zero = 0;
        __u32 key = 0;
        __u32 next_key = 0;

        // Start iteration over inner map keys (subscriber IPs)
        if (bpf_map_get_next_key(inner_map, NULL, &key) < 0)
            return TC_ACT_OK;

        // Modify headers
        __u8 temp_mac[ETH_ALEN];
        __builtin_memcpy(temp_mac, eth->h_source, ETH_ALEN);
        __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
        __builtin_memcpy(eth->h_dest, temp_mac, ETH_ALEN);

        __be32 temp_ip = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = temp_ip;

        __be16 temp_port = udp->source;
        udp->source = udp->dest;
        udp->dest = temp_port;

#pragma clang loop unroll(disable)
        for (int j = 0; j < 32; j++) {
            
            if (bpf_map_get_next_key(inner_map, &key, &next_key) < 0)
                break;
            key = next_key;

            // Re-derive packet pointers
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;

            eth = data;
            if ((void *)(eth + 1) > data_end) break;
            ip = (void *)(eth + 1);
            if ((void *)(ip + 1) > data_end) break;
            udp = (void *)(ip + 1);
            if ((void *)(udp + 1) > data_end) break;

            // Write fields — now safe
            ip->daddr = key;
            udp->dest = udp->source;

            bpf_clone_redirect(skb, skb->ifindex, 0);
        }
        return TC_ACT_SHOT;
    }
}

char LICENSE[] SEC("license") = "GPL";
