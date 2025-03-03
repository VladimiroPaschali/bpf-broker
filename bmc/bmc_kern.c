#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include "bmc_common.h"


/* program maps */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, BMC_PROG_XDP_MAX);
} map_progs_xdp SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, BMC_PROG_TC_MAX);
} map_progs_tc SEC(".maps");

/* payload maps */
struct test_buffer {
    __u32 len;
    char buf[BMC_MAX_PACKET_LENGTH];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(unsigned int));
    __uint(value_size, sizeof(struct test_buffer));
    __uint(max_entries, 1);
} map_test_buffer SEC(".maps");


SEC("xdp")
int rx_filter(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	void *transp = data + sizeof(*eth) + sizeof(*ip);
	struct udphdr *udp;
	struct tcphdr *tcp;
	char *payload;
	__be16 dport;

	if (ip + 1 > data_end)
		return XDP_PASS;

	switch (ip->protocol) {
		case IPPROTO_UDP:
			udp = (struct udphdr *) transp;
			if (udp + 1 > data_end)
				return XDP_PASS;
			dport = udp->dest;
			payload = transp + sizeof(*udp);
			break;
		case IPPROTO_TCP:
			tcp = (struct tcphdr *) transp;
			if (tcp + 1 > data_end)
				return XDP_PASS;
			dport = tcp->dest;
			payload = transp + sizeof(*tcp);
			break;
		default:
			return XDP_PASS;
	}

	if (ip->protocol == IPPROTO_UDP && ntohs(dport) == 11211) {
		bpf_printk("UDP packet to port 11211 detected, processing...");
		unsigned int zero = 0, off = 0;

		bpf_printk("Enter rx_filter() Bounds checking");
#pragma clang loop unroll(disable)
		while (off < BMC_MAX_PACKET_LENGTH &&
			(payload + off + 1 < data_end) &&
			payload[off] == ' ') {
			off++;
		}

		bpf_printk("Enter rx_filter() off=%u", off);
		if (off < BMC_MAX_PACKET_LENGTH) {
			if ((void *)(long)ctx->data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + off >= data_end) {
				return XDP_PASS;
			}
			
			bpf_tail_call(ctx, &map_progs_xdp, BMC_PROG_XDP_STORE_MSG);
		}
	}

	return XDP_PASS;
}

SEC("xdp")
int store_msg(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    if (payload >= data_end) return XDP_PASS;

    unsigned int zero = 0;
    struct test_buffer *fd = bpf_map_lookup_elem(&map_test_buffer, &zero);
    if (!fd) return XDP_PASS;

	unsigned int i = 0;
	__u32 copy_limit = 100;
	unsigned int data_len = 0;
	bpf_printk("Copy limit: %u", copy_limit);

#pragma clang loop unroll(disable)
	for (; i < copy_limit; i++) {
		if (payload + i >= data && payload + i < data_end) {
			fd->buf[i] = payload[i];
			bpf_printk("Stored byte[%u]: 0x%02x (%c)", i, fd->buf[i], fd->buf[i]);
			data_len++;
		}
	}

	bpf_printk("Total stored bytes: %u", data_len);
	fd->len = data_len;

    // TODO: adjust tail and fix checksum
	// int err = bpf_xdp_adjust_tail(ctx, -1);
	// if (err < 0) {
	// 	bpf_printk("Failed to truncate packet, err: %d", err);
	// }
    
    return XDP_PASS;
}

SEC("tc")
int tc_ingress_logger(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct udphdr *udp;
    struct tcphdr *tcp;
    char *payload;
    __be16 dport;

    if ((void *)eth + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    ip = (void *)eth + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return TC_ACT_OK;

    switch (ip->protocol) {
        case IPPROTO_UDP:
            udp = (struct udphdr *)((void *)ip + sizeof(*ip));
            if ((void *)udp + sizeof(*udp) > data_end)
                return TC_ACT_OK;
            dport = udp->dest;
            payload = (void *)udp + sizeof(*udp);
            break;
        case IPPROTO_TCP:
            tcp = (struct tcphdr *)((void *)ip + sizeof(*ip));
            if ((void *)tcp + sizeof(*tcp) > data_end)
                return TC_ACT_OK;
            dport = tcp->dest;
            payload = (void *)tcp + sizeof(*tcp);
            break;
        default:
            return TC_ACT_OK;
    }

    if (ip->protocol == IPPROTO_UDP && ntohs(dport) == 11211) {
        bpf_printk("TC ingress: Packet to port 11211 detected, already processed by XDP");
        unsigned int zero = 0, off = 0;

#pragma clang loop unroll(disable)
        while (off < 100 && (payload + off + 1 < data_end) && payload[off] == ' ') {
            off++;
        }

        bpf_printk("TC ingress: Off=%u", off);
        if (off < 100) {
            if ((void *)(long)skb->data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + off >= data_end) {
                return TC_ACT_OK;
            }
            bpf_printk("TC ingress: Packet matches XDP-filtered criteria");
    
            __u8 temp_mac[ETH_ALEN];
            __builtin_memcpy(temp_mac, eth->h_source, ETH_ALEN);
            __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
            __builtin_memcpy(eth->h_dest, temp_mac, ETH_ALEN);
    
            __be32 temp_ip = ip->saddr;
            ip->saddr = ip->daddr;
            ip->daddr = temp_ip;
    
            if (ip->protocol == IPPROTO_UDP) {
                __be16 temp_port = udp->source;
                udp->source = udp->dest;
                udp->dest = temp_port;
            } else if (ip->protocol == IPPROTO_TCP) {
                __be16 temp_port = tcp->source;
                tcp->source = tcp->dest;
                tcp->dest = temp_port;
            }
    
            for (int i = 0; i < 2; i++) {
                int err = bpf_clone_redirect(skb, skb->ifindex, 0);
                if (err < 0) {
                    bpf_printk("Failed to clone packet, err: %d", err);
                }
                bpf_printk("Cloned packet %d successfully", i + 1);
            }
        }
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
