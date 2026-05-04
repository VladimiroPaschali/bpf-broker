#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>          // for close()
#include <sys/syscall.h>     // for syscall(), __NR_bpf
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <arpa/inet.h>    // for inet_ntoa()
#include <netinet/in.h>   // for sockaddr_in
#include <sys/socket.h>   // for socket
#include <fcntl.h>        // for fcntl()

#include <pthread.h>
#include <time.h>


#define MAX_TOPIC_ID_CHARS 20
#define MAX_CPUS 128


void *poll_rps_loop(void *arg) {
    int map_fd = *(int *)arg;
    __u32 key = 0;

    __u32 curr_values[MAX_CPUS] = {0};
    __u32 prev_values[MAX_CPUS] = {0};

    FILE *log = fopen("qps_log.txt", "a");
    if (!log) {
        perror("fopen");
        return NULL;
    }

    while (1) {
        sleep(1);

        if (bpf_map_lookup_elem(map_fd, &key, curr_values) != 0) {
            perror("bpf_map_lookup_elem");
            continue;
        }

        __u32 total = 0;
        for (int i = 0; i < MAX_CPUS; i++) {
            if (curr_values[i] > prev_values[i]) {
                total += (curr_values[i] - prev_values[i]);
            }
        }

        // printf("[QPS] %u requests/second\n", total);
        fprintf(log, "%u\n", total);   // log format: <QPS>
        fflush(log);

        // Save current snapshot for next delta comparison
        memcpy(prev_values, curr_values, sizeof(curr_values));
    }

    fclose(log);
    return NULL;
}


int add_subscriber(int outer_fd, int sub_count_fd, int first_sub_fd, const char *topic_name, __u32 ip, __u32 port) {
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

    // Insert port directly as value
    __u64 key = ((__u64)htonl(ip) << 32) | ((__u64)htons(port) << 16);
    // __u8 existing;
    // if (bpf_map_lookup_elem(inner_fd, &key, &existing) != 0) {
    //     printf("Subscriber %u:%u already exists in for topic '%s'\n", ip, port, topic_name);
    //     close(inner_fd);
    //     return 0;
    // }

    __u8 dummy = 1;
    if (bpf_map_update_elem(inner_fd, &key, &dummy, BPF_ANY) < 0) {
        perror("Failed to insert subscriber into inner map");
        close(inner_fd);
        return -1;
    }

    __u32 current = 0;
    if (bpf_map_lookup_elem(sub_count_fd, topic_key, &current) == 0) {
        current += 1;
    } else {
        current = 1;
    }
    
    if (bpf_map_update_elem(sub_count_fd, topic_key, &current, BPF_ANY) < 0) {
        perror("Failed to update topic_sub_cnt");
        close(inner_fd);
        return -1;
    }
    printf("Current sub count is %d for topic '%s'\n", current, topic_name);

    if (current == 1) {
        if (bpf_map_update_elem(first_sub_fd, topic_key, &key, BPF_ANY) < 0) {
            perror("Failed to store first subscriber key");
            close(inner_fd);
            return -1;
        }
    }

    char ip_str[INET_ADDRSTRLEN];
    struct in_addr ip_addr = { .s_addr = htonl(ip) };
    inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str));

    printf("Added subscriber %s:%u to topic '%s'\n", ip_str, port, topic_name);
    close(inner_fd);
    return 0;
}


int add_topic(int outer_fd, const char *topic_name) {
    int inner_fd;

    // Format fixed-size topic key
    char topic_key[MAX_TOPIC_ID_CHARS] = {0};
    size_t len = strlen(topic_name);
    if (len >= MAX_TOPIC_ID_CHARS) {
        fprintf(stderr, "[add_topic] Topic name too long (max %d chars)\n", MAX_TOPIC_ID_CHARS - 1);
        return -1;
    }
    memcpy(topic_key, topic_name, len);

    // Early return if topic already exists
    int tmp_fd = 0;
    int ret = bpf_map_lookup_elem(outer_fd, topic_key, &tmp_fd);
    if (ret == 0) {
        printf("[add_topic] Topic '%s' already exists (inner map fd = %d)\n", topic_name, tmp_fd);
        return 0;
    }

    // Define the inner map attributes
    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__u64),
        .value_size = sizeof(__u32),
        .max_entries = 256,
    };

    // Create the inner map
    inner_fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    if (inner_fd < 0) {
        perror("[add_topic] Failed to create inner subscriber_map");
        return -1;
    }

    // Need to cast inner_fd to __u32 for insertion
    __u32 inner_fd_u32 = (__u32)inner_fd;

    // Insert into outer map
    int update_ret = bpf_map_update_elem(outer_fd, topic_key, &inner_fd_u32, BPF_ANY);
    // printf("[add_topic] bpf_map_update_elem(outer_fd=%d, key='%s', inner_fd_u32=%u) => %d\n",
    //        outer_fd, topic_key, inner_fd_u32, update_ret);

    if (update_ret < 0) {
        perror("[add_topic] Failed to insert topic into topic_subscribe");
        close(inner_fd);
        return -1;
    }

    printf("[add_topic] Added topic '%s' with inner map fd %d\n", topic_name, inner_fd);
    close(inner_fd);
    return 0;
}


int main() {
    printf("Starting BPF-Broker...\n");
    int outer_fd = bpf_obj_get("/sys/fs/bpf/topic_subscribe");
    if (outer_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }
    printf("BPF-Broker: outer_fd = %d\n", outer_fd);

    int sub_count_fd = bpf_obj_get("/sys/fs/bpf/topic_sub_cnt");
    if (sub_count_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }
    printf("BPF-Broker: sub_count_fd = %d\n", sub_count_fd);
    int first_sub_fd = bpf_obj_get("/sys/fs/bpf/topic_first_sub");
    if (first_sub_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }
    printf("BPF-Broker: first_sub_fd = %d\n", first_sub_fd);
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    // int publish_counter_fd = bpf_obj_get("/sys/fs/bpf/publish_counter");
    // if (publish_counter_fd < 0) {
    //     perror("bpf_obj_get (publish_counter)");
    //     return 1;
    // }

    // pthread_t rps_thread;
    // if (pthread_create(&rps_thread, NULL, poll_rps_loop, &publish_counter_fd) != 0) {
    //     perror("pthread_create");
    //     return 1;
    // }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(49152),
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

        buf[len] = '\0';  // Null-terminate for safe parsing

        if (strncmp(buf, "REGISTER ", 9) == 0) {
            char topic_key[MAX_TOPIC_ID_CHARS] = {0};

            // Extract topic name (rest of line after "REGISTER ")
            const char *topic_raw = buf + 9;

            // Trim trailing newline/space and copy up to MAX_TOPIC_ID_CHARS
            size_t topic_len = strnlen(topic_raw, MAX_TOPIC_ID_CHARS);
            strncpy(topic_key, topic_raw, topic_len);

            // Trim trailing newline if present
            for (int i = 0; i < MAX_TOPIC_ID_CHARS; i++) {
                if (topic_key[i] == '\n' || topic_key[i] == '\r') {
                    topic_key[i] = '\0';
                    break;
                }
            }

            printf("REGISTER '%s' from %s\n",
                   topic_key, inet_ntoa(client.sin_addr));

            if (add_topic(outer_fd, topic_key) == 0) {
                // Send REGACK response
                char response[256];
                snprintf(response, sizeof(response), "REGACK %s", topic_key);
                if (sendto(sock, response, strlen(response), 0,
                          (struct sockaddr *)&client, client_len) < 0) {
                    perror("sendto");
                }
                // add_subscriber(outer_fd, topic_key, ip, port);
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

            __u32 ip = ntohl(client.sin_addr.s_addr);
            __u32 port = ntohs(client.sin_port);

            printf("SUBSCRIBE '%s' from %s\n", 
                   topic_key, inet_ntoa(client.sin_addr));

            add_subscriber(outer_fd, sub_count_fd, first_sub_fd, topic_key, ip, port);

            char response[256];
            snprintf(response, sizeof(response), "SUBACK %s", topic_key);
            if (sendto(sock, response, strlen(response), 0,
                      (struct sockaddr *)&client, client_len) < 0) {
                perror("sendto");
            }
        } else {
            printf("Unknown command: '%s'\n", buf);
        }
    }

    close(sock);
    close(outer_fd);
    close(sub_count_fd);
    close(first_sub_fd);
    return 0;
}
