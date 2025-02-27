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

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bmc_common.h"

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
    {"rx_filter", BPF_PROG_TYPE_XDP, 0, -1, NULL},
	{"store_msg", BPF_PROG_TYPE_XDP, 0, BMC_PROG_XDP_STORE_MSG, NULL},
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
							const char *format, va_list args)
{
	return vfprintf(stdout, format, args);
}


int main(int argc, char *argv[])
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	int map_progs_xdp_fd, xdp_main_prog_fd, map_progs_tc_fd, map_progs_fd;
	struct bpf_object *obj;
	char filename[PATH_MAX];
	int err, prog_count;
	__u32 xdp_flags = 0;
	int *interfaces_idx;
	int ret = 0;

	int interface_count = argc - 1;
	if (interface_count <= 0) {
		fprintf(stderr, "Missing at least one required interface index\n");
		exit(EXIT_FAILURE);
	}

	interfaces_idx = calloc(sizeof(int), interface_count);
	if (interfaces_idx == NULL) {
		fprintf(stderr, "Error: failed to allocate memory\n");
		return 1;
	}

	for (int i = 0; i < interface_count; i++) {
        interfaces_idx[i] = atoi(argv[i + 1]);
        if (interfaces_idx[i] <= 0) {
            fprintf(stderr, "Invalid interface index: %s\n", argv[i + 1]);
            free(interfaces_idx);
            exit(EXIT_FAILURE);
        }
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

	map_progs_xdp_fd = bpf_object__find_map_fd_by_name(obj, "map_progs_xdp");
	if (map_progs_xdp_fd < 0) {
		fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
		return 1;
	}

	map_progs_tc_fd = bpf_object__find_map_fd_by_name(obj, "map_progs_tc");
	if (map_progs_tc_fd < 0) {
		fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
		return 1;
	}

	for (int i = 0; i < prog_count; i++) {
		int prog_fd = bpf_program__fd(progs[i].prog);

		if (prog_fd < 0) {
			fprintf(stderr, "Error: Couldn't get file descriptor for program %s\n", progs[i].name);
			return 1;
		}

    	printf("Program[%d]: Name=%s, FD=%d\n", i, progs[i].name, prog_fd);

		if (progs[i].map_prog_idx != -1) {
			unsigned int map_prog_idx = progs[i].map_prog_idx;
			if (map_prog_idx < 0) {
				fprintf(stderr, "Error: Cannot get prog fd for bpf program %s\n", progs[i].name);
				return 1;
			}

			switch (progs[i].type) {
			case BPF_PROG_TYPE_XDP:
				map_progs_fd = map_progs_xdp_fd;
				break;
			case BPF_PROG_TYPE_SCHED_CLS:
				map_progs_fd = map_progs_tc_fd;
				break;
			default:
				fprintf(stderr, "Error: Program type doesn't correspond to any prog array map\n");
				return 1;
			}

			err = bpf_map_update_elem(map_progs_fd, &map_prog_idx, &prog_fd, 0);
			if (err) {
				fprintf(stderr, "Error: bpf_map_update_elem failed for prog array map\n");
				return 1;
			}
		}

		if (progs[i].pin) {
			int len = snprintf(filename, PATH_MAX, "%s/%s", BPF_SYSFS_ROOT, progs[i].name);
			if (len < 0) {
				fprintf(stderr, "Error: Program name '%s' is invalid\n", progs[i].name);
				return -1;
			} else if (len >= PATH_MAX) {
				fprintf(stderr, "Error: Program name '%s' is too long\n", progs[i].name);
				return -1;
			}
retry:
			if (bpf_program__pin(progs[i].prog, filename)) {
				fprintf(stderr, "Error: Failed to pin program '%s' to path %s\n", progs[i].name, filename);
				if (errno == EEXIST) {
					fprintf(stdout, "BPF program '%s' already pinned, unpinning it to reload it\n", progs[i].name);
					if (bpf_program__unpin(progs[i].prog, filename)) {
						fprintf(stderr, "Error: Fail to unpin program '%s' at %s\n", progs[i].name, filename);
						return -1;
					}
					goto retry;
				}
				return -1;
			}
		}
	}

	xdp_main_prog_fd = bpf_program__fd(progs[0].prog);
	if (xdp_main_prog_fd < 0) {
		fprintf(stderr, "Error: bpf_program__fd failed\n");
		return 1;
	}

	for (int i = 0; i < interface_count; i++) {
		if (bpf_xdp_attach(interfaces_idx[i], xdp_main_prog_fd, xdp_flags, NULL) < 0) {
			fprintf(stderr, "Error: bpf_xdp_attach failed for interface %d\n", interfaces_idx[i]);
			return 1;
		} else {
			printf("Main BPF program attached to XDP on interface %d\n", interfaces_idx[i]);
		}
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

	return ret;
}
