/*
 *  Software Name : bpf-broker
 *  SPDX-FileCopyrightText: Copyright (c) 2021 Orange
 *  SPDX-License-Identifier: LGPL-2.1-only
 *
 *  This software is distributed under the
 *  GNU Lesser General Public License v2.1 only.
 *
 *  Author: Yoann GHIGOFF <yoann.ghigoff@orange.com> et al.
 */

#ifndef _BPF_BROKER_COMMON_H
#define _BPF_BROKER_COMMON_H

#define BPF_BROKER_MAX_KEY_LENGTH 250
#define BPF_BROKER_MAX_VAL_LENGTH 1000
#define BPF_BROKER_MAX_ADDITIONAL_PAYLOAD_BYTES 53
#define BPF_BROKER_MAX_CACHE_DATA_SIZE BPF_BROKER_MAX_KEY_LENGTH+BPF_BROKER_MAX_VAL_LENGTH+BPF_BROKER_MAX_ADDITIONAL_PAYLOAD_BYTES
#define BPF_BROKER_MAX_KEY_IN_MULTIGET 30
#define BPF_BROKER_CACHE_ENTRY_COUNT 3250000
#define BPF_BROKER_MAX_PACKET_LENGTH 1500
#define BPF_BROKER_MAX_KEY_IN_PACKET BPF_BROKER_MAX_KEY_IN_MULTIGET

#define FNV_OFFSET_BASIS_32		2166136261
#define FNV_PRIME_32			16777619

enum {
	BPF_BROKER_PROG_XDP_HASH_KEYS = 0,
	BPF_BROKER_PROG_XDP_PREPARE_PACKET,
	BPF_BROKER_PROG_XDP_WRITE_REPLY,
	BPF_BROKER_PROG_XDP_INVALIDATE_CACHE,
	BPF_BROKER_PROG_XDP_STORE_MSG,

	BPF_BROKER_PROG_XDP_MAX
};

enum {
	BPF_BROKER_PROG_TC_UPDATE_CACHE = 0,

	BPF_BROKER_PROG_TC_MAX
};


struct bpf_broker_cache_entry {
	struct bpf_spin_lock lock;
	unsigned int len;
	char valid;
	int hash;
	char data[BPF_BROKER_MAX_CACHE_DATA_SIZE];
};

struct bpf_broker_stats {
	unsigned int pub_recv_count;
	unsigned int sub_recv_count;
};

#endif
