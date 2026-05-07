#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <sys/resource.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <net/if.h>
#include <ctype.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define BPF_SYSFS_ROOT "/sys/fs/bpf"


static int nr_cpus = 0;

struct bpf_progs_desc {
	char name[256];
	enum bpf_prog_type type;
	unsigned char pin;
	int map_prog_idx;
	struct bpf_program *prog;
};

static struct bpf_progs_desc progs[] = {
	{"xdp_broker", BPF_PROG_TYPE_XDP, 0, -1, NULL},
};

struct bpf_map_pin_desc {
	const char *map_name;
};

static struct bpf_map_pin_desc maps[] = {
	{ "topic_sub_array" },
	{ "topic_sub_cnt" },
	{ "pub_counter_2" },
};

void list_bpf_programs(struct bpf_object *obj) {
    struct bpf_program *prog;

    printf("Listing all BPF programs in the object file:\n");
    bpf_object__for_each_program(prog, obj) {
        const char *sec_name = bpf_program__section_name(prog);
        const char *prog_name = bpf_program__name(prog);
        printf(" - Section: %s, Name: %s\n", sec_name ? sec_name : "(unknown)", prog_name ? prog_name : "(unnamed)");
    }
}


static int print_bpf_verifier(enum libbpf_print_level level,
							const char *format, va_list args) {
	return vfprintf(stdout, format, args);
}

int pin_map(struct bpf_object *obj, const char *map_name) {
	int map_fd = bpf_object__find_map_fd_by_name(obj, map_name);
	if (map_fd < 0) {
		fprintf(stderr, "Error: Failed to find '%s' map\n", map_name);
		return -1;
	}

	char pin_path[PATH_MAX];
	snprintf(pin_path, sizeof(pin_path), "%s/%s", BPF_SYSFS_ROOT, map_name);

	if (bpf_obj_pin(map_fd, pin_path) != 0) {
		if (errno == EEXIST) {
			fprintf(stdout, "'%s' already pinned, unpinning to replace\n", map_name);
			// Close the old pinned map first
			int old_fd = bpf_obj_get(pin_path);
			if (old_fd >= 0) {
				close(old_fd);
			}
			// Now remove the pin
			if (unlink(pin_path) != 0) {
				perror("Failed to remove existing pin");
				return -1;
			}
			// Pin the new map
			if (bpf_obj_pin(map_fd, pin_path) != 0) {
				perror("Failed to re-pin map");
				return -1;
			}
		} else {
			perror("Failed to pin map");
			return -1;
		}
	}
	return 0;
}

static int resolve_interface(const char *arg) {
	int idx;
	char *endptr;
	
	// Try to parse as integer first
	idx = strtol(arg, &endptr, 10);
	if (*endptr == '\0' && idx > 0) {
		// It's a valid integer index
		return idx;
	}
	
	// Try to resolve as interface name
	idx = if_nametoindex(arg);
	if (idx == 0) {
		fprintf(stderr, "Error: Interface '%s' not found\n", arg);
		return -1;
	}
	
	printf("Resolved interface '%s' to index %d\n", arg, idx);
	return idx;
}

int main(int argc, char *argv[])
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	int xdp_main_prog_fd;
	struct bpf_object *obj;
	char filename[PATH_MAX];
	int err, prog_count;
	__u32 xdp_flags = 0;
	int *interfaces_idx;
	int ret = 0;

	int interface_count = argc - 1;
	if (interface_count <= 0) {
		fprintf(stderr, "Usage: %s <interface_index_or_name> [interface_index_or_name ...]\n", argv[0]);
		fprintf(stderr, "Examples: %s 38\n", argv[0]);
		fprintf(stderr, "Examples: %s enp52s0f1np1\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	interfaces_idx = calloc(sizeof(int), interface_count);
	if (interfaces_idx == NULL) {
		fprintf(stderr, "Error: failed to allocate memory\n");
		return 1;
	}

	for (int i = 0; i < interface_count; i++) {
		int idx = resolve_interface(argv[i + 1]);
		if (idx <= 0) {
			free(interfaces_idx);
			exit(EXIT_FAILURE);
		}
		interfaces_idx[i] = idx;
    }

	xdp_flags |= XDP_FLAGS_DRV_MODE;
	nr_cpus = libbpf_num_possible_cpus();

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGINT);
	sigaddset(&signal_mask, SIGTERM);
	sigaddset(&signal_mask, SIGUSR1);

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit failed");
		return 1;
	}
	libbpf_set_print(print_bpf_verifier);

	obj = bpf_object__open(filename);
	if (!obj) {
		fprintf(stderr, "Error: bpf_object__open failed\n");
		return 1;
	}

	list_bpf_programs(obj);

	prog_count = sizeof(progs) / sizeof(progs[0]);

	for (int i = 0; i < prog_count; i++) {
		progs[i].prog = bpf_object__find_program_by_name(obj, progs[i].name);
		if (!progs[i].prog) {
			fprintf(stderr, "Error: bpf_object__find_program_by_name failed\n");
			return 1;
		}
		bpf_program__set_type(progs[i].prog, progs[i].type);
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "Error: bpf_object__load failed\n");
		return 1;
	}

	for (int i = 0; i < prog_count; i++) {
		int prog_fd = bpf_program__fd(progs[i].prog);
		if (prog_fd < 0) {
			fprintf(stderr, "Error: Couldn't get file descriptor for program %s\n", progs[i].name);
			return 1;
		}
		printf("Program[%d]: Name=%s, FD=%d\n", i, progs[i].name, prog_fd);
	}

	xdp_main_prog_fd = bpf_program__fd(progs[0].prog);
	if (xdp_main_prog_fd < 0) {
		fprintf(stderr, "Error: bpf_program__fd failed\n");
		return 1;
	}

	for (int i = 0; i < interface_count; i++) {
		if (bpf_xdp_attach(interfaces_idx[i], xdp_main_prog_fd, xdp_flags, NULL) < 0) {
			fprintf(stderr, "Error: bpf_xdp_attach failed for interface %d: %s (errno=%d)\n",
				interfaces_idx[i], strerror(errno), errno);
			return 1;
		}
		printf("XDP program attached to interface %d\n", interfaces_idx[i]);
	}

	int map_count = sizeof(maps) / sizeof(maps[0]);
	for (int i = 0; i < map_count; i++) {
		if (pin_map(obj, maps[i].map_name) < 0)
			return -1;
	}

	int sig, quit = 0;

	err = sigprocmask(SIG_BLOCK, &signal_mask, NULL);
	if (err != 0) {
		fprintf(stderr, "Error: Failed to set signal mask\n");
		exit(EXIT_FAILURE);
	}

	while (!quit) {
		err = sigwait(&signal_mask, &sig);
		if (err != 0) {
			fprintf(stderr, "Error: Failed to wait for signal\n");
			exit(EXIT_FAILURE);
		}

		switch (sig) {
			case SIGINT:
			case SIGTERM:
			case SIGUSR1:
				quit = 1;
				break;
			default:
				fprintf(stderr, "Unknown signal\n");
				break;
		}
	}

	for (int i = 0; i < interface_count; i++) {
		bpf_xdp_attach(interfaces_idx[i], -1, xdp_flags, NULL);
	}
	free(interfaces_idx);

	return ret;
}
