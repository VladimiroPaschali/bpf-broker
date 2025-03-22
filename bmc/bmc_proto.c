#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>          // for close()
#include <sys/syscall.h>     // for syscall(), __NR_bpf
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MAX_TOPIC_ID_CHARS 20


int add_subscriber(int outer_fd, const char *topic_name, __u32 ip, __u32 dummy_val) {
    char topic_key[MAX_TOPIC_ID_CHARS] = {0};
    size_t len = strlen(topic_name);
    if (len >= MAX_TOPIC_ID_CHARS) {
        fprintf(stderr, "Topic name too long (max %d chars)\n", MAX_TOPIC_ID_CHARS - 1);
        return -1;
    }
    memcpy(topic_key, topic_name, len);

    __u32 inner_id;
    if (bpf_map_lookup_elem(outer_fd, topic_key, &inner_id) < 0) {
        perror("Failed to find topic in outer map");
        return -1;
    }

    int inner_fd = bpf_map_get_fd_by_id(inner_id);
    if (inner_fd < 0) {
        perror("bpf_map_get_fd_by_id");
        return -1;
    }

    // Insert subscriber IP into the inner map
    if (bpf_map_update_elem(inner_fd, &ip, &dummy_val, BPF_ANY) < 0) {
        perror("Failed to insert subscriber into inner map");
        close(inner_fd);
        return -1;
    }

    printf("Added subscriber IP 0x%x -> %u to topic '%s'\n", ip, dummy_val, topic_name);
    close(inner_fd);
    return 0;
}


int add_topic(int outer_fd, const char *topic_name) {
    int inner_fd;

    // Format fixed-size topic key
    char topic_key[MAX_TOPIC_ID_CHARS] = {0};
    size_t len = strlen(topic_name);
    if (len >= MAX_TOPIC_ID_CHARS) {
        fprintf(stderr, "Topic name too long (max %d chars)\n", MAX_TOPIC_ID_CHARS - 1);
        return -1;
    }
    memcpy(topic_key, topic_name, len);

    // Early return if topic already exists
    if (bpf_map_lookup_elem(outer_fd, topic_key, &inner_fd) == 0) {
        printf("Topic '%s' already exists (inner map fd = %d)\n", topic_name, inner_fd);
        return 0;
    }

    // Create inner subscriber map
    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__u32),
        .value_size = sizeof(__u32),
        .max_entries = 256,
    };
    inner_fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    if (inner_fd < 0) {
        perror("Failed to create inner subscriber_map");
        return -1;
    }

    // Insert inner map into outer map
    if (bpf_map_update_elem(outer_fd, topic_key, &inner_fd, BPF_ANY) < 0) {
        perror("Failed to insert topic into topic_subscribe");
        close(inner_fd);
        return -1;
    }

    printf("Added topic '%s' with inner map fd %d\n", topic_name, inner_fd);
    close(inner_fd);
    return 0;
}


int main() {
    int outer_fd = bpf_obj_get("/sys/fs/bpf/topic_subscribe");
    if (outer_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    // Add a new topic
    add_topic(outer_fd, "test");

    // Add a subscriber to that topic
    __u32 ip = (192 << 24) | (168 << 16) | (1 << 8) | 100;  // 192.168.1.100
    add_subscriber(outer_fd, "test", ip, 1);

    close(outer_fd);

    return 0;
}
