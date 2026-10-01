#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <bpf/libbpf.h>

#include "syscall_monitor.skel.h"

static volatile sig_atomic_t exiting = 0;

struct syscall_event {
    unsigned int pid;
    unsigned int uid;
    unsigned long long timestamp_ns;
    char comm[16];
};

static void sig_handler(int sig)
{
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct syscall_event *event = data;

    double timestamp_sec =
        event->timestamp_ns / 1000000000.0;

    printf(
        "openat syscall | PID: %u | UID: %u | Time: %.3f sec | Process: %s\n",
        event->pid,
        event->uid,
        timestamp_sec,
        event->comm
    );

    return 0;
}

int main(void)
{
    struct syscall_monitor_bpf *skel;
    struct ring_buffer *rb;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = syscall_monitor_bpf__open_and_load();

    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = syscall_monitor_bpf__attach(skel);

    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        syscall_monitor_bpf__destroy(skel);
        return 1;
    }

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        NULL,
        NULL
    );

    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        syscall_monitor_bpf__destroy(skel);
        return 1;
    }

    printf("eBPF syscall monitor started.\n");
    printf("Monitoring openat system calls...\n");
    printf("Press Ctrl+C to stop.\n\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);

        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Ring buffer polling failed: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    syscall_monitor_bpf__destroy(skel);

    printf("\nSyscall monitor stopped.\n");

    return 0;
}
