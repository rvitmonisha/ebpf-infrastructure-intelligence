// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct network_event {
    __u32 pid;
    __u32 uid;
    __u64 timestamp_ns;
    __u16 family;
    __u16 sport;
    __u16 dport;
    __u32 saddr;
    __u32 daddr;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int trace_tcp_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    struct network_event *event;

    /*
     * TCP_ESTABLISHED = 1
     * Capture only successfully established TCP connections.
     */
    if (ctx->newstate != 1)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    event->pid = pid_tgid >> 32;
    event->uid = (__u32)bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();

    event->family = ctx->family;
    event->sport = ctx->sport;
    event->dport = ctx->dport;

    /*
     * vmlinux.h represents saddr and daddr as
     * 4-byte arrays, so copy the address bytes.
     */
    __builtin_memcpy(
        &event->saddr,
        ctx->saddr,
        sizeof(event->saddr)
    );

    __builtin_memcpy(
        &event->daddr,
        ctx->daddr,
        sizeof(event->daddr)
    );

    bpf_get_current_comm(
        event->comm,
        sizeof(event->comm)
    );

    bpf_ringbuf_submit(event, 0);

    return 0;
}
