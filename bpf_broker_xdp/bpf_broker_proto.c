#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define MAX_TOPIC_ID_CHARS 20
#define MAX_SUBSCRIBERS 2048


int add_subscriber(int outer_fd, int sub_count_fd, const char *topic_name, __u32 ip, __u32 port) {
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

    /* Read current sub count — this is the next free array index. */
    __u32 idx = 0;
    bpf_map_lookup_elem(sub_count_fd, topic_key, &idx);

    /* packed: bits 63:32 = ip (network order), bits 31:16 = port (network order) */
    __u64 packed = ((__u64)htonl(ip) << 32) | ((__u64)htons(port) << 16);

    if (bpf_map_update_elem(inner_fd, &idx, &packed, BPF_ANY) < 0) {
        perror("Failed to insert subscriber into inner array");
        close(inner_fd);
        return -1;
    }

    __u32 new_count = idx + 1;
    if (bpf_map_update_elem(sub_count_fd, topic_key, &new_count, BPF_ANY) < 0) {
        perror("Failed to update topic_sub_cnt");
        close(inner_fd);
        return -1;
    }

    char ip_str[INET_ADDRSTRLEN];
    struct in_addr ip_addr = { .s_addr = htonl(ip) };
    inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str));

    printf("Added subscriber %s:%u to topic '%s' at index %u\n", ip_str, port, topic_name, idx);
    close(inner_fd);
    return 0;
}


int flush_topic(int outer_fd, int sub_count_fd, const char *topic_name) {
    char topic_key[MAX_TOPIC_ID_CHARS] = {0};
    size_t len = strlen(topic_name);
    if (len >= MAX_TOPIC_ID_CHARS) {
        fprintf(stderr, "Topic name too long\n");
        return -1;
    }
    memcpy(topic_key, topic_name, len);

    __u32 count = 0;
    bpf_map_lookup_elem(sub_count_fd, topic_key, &count);

    if (count == 0) {
        printf("[flush] topic '%s': no subscribers, nothing to do\n", topic_name);
        return 0;
    }

    __u32 inner_id;
    if (bpf_map_lookup_elem(outer_fd, topic_key, &inner_id) < 0) {
        fprintf(stderr, "[flush] topic '%s' not found\n", topic_name);
        return 0;
    }

    int inner_fd = bpf_map_get_fd_by_id(inner_id);
    if (inner_fd < 0) {
        perror("[flush] bpf_map_get_fd_by_id");
        return -1;
    }

    /* ARRAY entries can't be deleted — zero out entries 0..count-1. */
    __u64 zero = 0;
    for (__u32 i = 0; i < count; i++) {
        bpf_map_update_elem(inner_fd, &i, &zero, BPF_ANY);
    }
    close(inner_fd);

    /* Reset count to 0: XDP checks sub_count == 0 → XDP_PASS (no clones). */
    __u32 new_count = 0;
    bpf_map_update_elem(sub_count_fd, topic_key, &new_count, BPF_ANY);

    printf("[flush] topic '%s': cleared %u subscribers\n", topic_name, count);
    return 0;
}


int add_topic(int outer_fd, const char *topic_name) {
    char topic_key[MAX_TOPIC_ID_CHARS] = {0};
    size_t len = strlen(topic_name);
    if (len >= MAX_TOPIC_ID_CHARS) {
        fprintf(stderr, "[add_topic] Topic name too long (max %d chars)\n", MAX_TOPIC_ID_CHARS - 1);
        return -1;
    }
    memcpy(topic_key, topic_name, len);

    __u32 tmp_id = 0;
    if (bpf_map_lookup_elem(outer_fd, topic_key, &tmp_id) == 0) {
        printf("[add_topic] Topic '%s' already exists\n", topic_name);
        return 0;
    }

    /* Inner map: u32 index → u64 packed subscriber — must match subscriber_array_inner in kern.c */
    union bpf_attr attr = {
        .map_type   = BPF_MAP_TYPE_ARRAY,
        .key_size   = sizeof(__u32),
        .value_size = sizeof(__u64),
        .max_entries = MAX_SUBSCRIBERS,
    };

    int inner_fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    if (inner_fd < 0) {
        perror("[add_topic] Failed to create inner subscriber array");
        return -1;
    }

    __u32 inner_fd_u32 = (__u32)inner_fd;
    if (bpf_map_update_elem(outer_fd, topic_key, &inner_fd_u32, BPF_ANY) < 0) {
        perror("[add_topic] Failed to insert topic into topic_sub_array");
        close(inner_fd);
        return -1;
    }

    printf("[add_topic] Added topic '%s' with inner array fd %d\n", topic_name, inner_fd);
    close(inner_fd);
    return 0;
}


int main() {
    printf("Starting BPF-Broker (XDP-only)...\n");

    int outer_fd = bpf_obj_get("/sys/fs/bpf/topic_sub_array");
    if (outer_fd < 0) {
        perror("bpf_obj_get /sys/fs/bpf/topic_sub_array");
        return 1;
    }
    printf("BPF-Broker: outer_fd = %d\n", outer_fd);

    int sub_count_fd = bpf_obj_get("/sys/fs/bpf/topic_sub_cnt");
    if (sub_count_fd < 0) {
        perror("bpf_obj_get /sys/fs/bpf/topic_sub_cnt");
        return 1;
    }
    printf("BPF-Broker: sub_count_fd = %d\n", sub_count_fd);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port        = htons(49152),
    };

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    printf("Listening for UDP on port 49152...\n");

    char buf[1024];
    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);

    while (1) {
        ssize_t len = recvfrom(sock, buf, sizeof(buf) - 1, 0,
                               (struct sockaddr *)&client, &client_len);
        if (len < 0) {
            perror("recvfrom");
            continue;
        }
        buf[len] = '\0';

        if (strncmp(buf, "REGISTER ", 9) == 0) {
            char topic_key[MAX_TOPIC_ID_CHARS] = {0};
            const char *topic_raw = buf + 9;
            size_t topic_len = strnlen(topic_raw, MAX_TOPIC_ID_CHARS);
            strncpy(topic_key, topic_raw, topic_len);
            for (int i = 0; i < MAX_TOPIC_ID_CHARS; i++) {
                if (topic_key[i] == '\n' || topic_key[i] == '\r') {
                    topic_key[i] = '\0';
                    break;
                }
            }

            printf("REGISTER '%s' from %s\n", topic_key, inet_ntoa(client.sin_addr));

            if (add_topic(outer_fd, topic_key) == 0) {
                char response[256];
                snprintf(response, sizeof(response), "REGACK %s", topic_key);
                if (sendto(sock, response, strlen(response), 0,
                           (struct sockaddr *)&client, client_len) < 0) {
                    perror("sendto");
                }
            }

        } else if (strncmp(buf, "SUBSCRIBE ", 10) == 0) {
            char topic_key[MAX_TOPIC_ID_CHARS] = {0};
            const char *topic_raw = buf + 10;
            size_t topic_len = strnlen(topic_raw, MAX_TOPIC_ID_CHARS);
            strncpy(topic_key, topic_raw, topic_len);
            for (int i = 0; i < MAX_TOPIC_ID_CHARS; i++) {
                if (topic_key[i] == '\n' || topic_key[i] == '\r') {
                    topic_key[i] = '\0';
                    break;
                }
            }

            __u32 ip   = ntohl(client.sin_addr.s_addr);
            __u32 port = ntohs(client.sin_port);

            printf("SUBSCRIBE '%s' from %s\n", topic_key, inet_ntoa(client.sin_addr));

            add_subscriber(outer_fd, sub_count_fd, topic_key, ip, port);

            char response[256];
            snprintf(response, sizeof(response), "SUBACK %s", topic_key);
            if (sendto(sock, response, strlen(response), 0,
                       (struct sockaddr *)&client, client_len) < 0) {
                perror("sendto");
            }

        } else if (strncmp(buf, "FLUSH ", 6) == 0) {
            char topic_key[MAX_TOPIC_ID_CHARS] = {0};
            const char *topic_raw = buf + 6;
            size_t topic_len = strnlen(topic_raw, MAX_TOPIC_ID_CHARS);
            strncpy(topic_key, topic_raw, topic_len);
            for (int i = 0; i < MAX_TOPIC_ID_CHARS; i++) {
                if (topic_key[i] == '\n' || topic_key[i] == '\r') {
                    topic_key[i] = '\0';
                    break;
                }
            }
            flush_topic(outer_fd, sub_count_fd, topic_key);
            char response[] = "FLUSHED";
            sendto(sock, response, strlen(response), 0, (struct sockaddr *)&client, client_len);

        } else {
            printf("Unknown command: '%s'\n", buf);
        }
    }

    close(sock);
    close(outer_fd);
    close(sub_count_fd);
    return 0;
}
