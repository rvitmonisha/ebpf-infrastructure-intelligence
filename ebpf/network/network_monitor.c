#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>

#include "network_monitor.skel.h"

static volatile sig_atomic_t exiting = 0;

struct network_event {
    unsigned int pid;
    unsigned int uid;
    unsigned long long timestamp_ns;
    unsigned short family;
    unsigned short sport;
    unsigned short dport;
    unsigned int saddr;
    unsigned int daddr;
    char comm[16];
};

static void sig_handler(int sig)
{
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct network_event *event = data;

    double timestamp_sec =
        event->timestamp_ns / 1000000000.0;

    struct in_addr source_addr;
    struct in_addr destination_addr;

    source_addr.s_addr = event->saddr;
    destination_addr.s_addr = event->daddr;

    printf(
        "TCP connection | PID: %u | UID: %u | "
        "Process: %s | %s:%u -> %s:%u | Time: %.3f sec\n",
        event->pid,
        event->uid,
        event->comm,
        inet_ntoa(source_addr),
        event->sport,
        inet_ntoa(destination_addr),
        event->dport,
        timestamp_sec
    );

    return 0;
}

int main(void)
{
    struct network_monitor_bpf *skel;
    struct ring_buffer *rb;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = network_monitor_bpf__open_and_load();

    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = network_monitor_bpf__attach(skel);

    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        network_monitor_bpf__destroy(skel);
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
        network_monitor_bpf__destroy(skel);
        return 1;
    }

    printf("eBPF network monitor started.\n");
    printf("Monitoring established TCP connections...\n");
    printf("Press Ctrl+C to stop.\n\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);

        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Ring buffer polling failed: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    network_monitor_bpf__destroy(skel);

    printf("\nNetwork monitor stopped.\n");

    return 0;
}
