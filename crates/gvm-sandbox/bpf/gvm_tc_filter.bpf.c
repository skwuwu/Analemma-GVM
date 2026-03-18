// SPDX-License-Identifier: Apache-2.0
//
// GVM TC egress filter — attached to host-side veth interface.
//
// This eBPF program enforces proxy-only network access at the kernel level.
// Because it runs on the HOST-side veth (outside the agent's namespace),
// the agent cannot modify or detach it — even with CAP_NET_ADMIN inside
// its user namespace.
//
// Allowed traffic:
//   - TCP to PROXY_IP:PROXY_PORT (GVM proxy)
//   - UDP to PROXY_IP:53 (DNS resolution via host)
//   - ARP (required for veth L2 resolution)
//
// All other traffic is dropped (TC_ACT_SHOT).
//
// Build: clang -O2 -g -target bpf -c gvm_tc_filter.bpf.c -o gvm_tc_filter.o
// Load:  tc qdisc add dev <veth-host> clsact
//        tc filter add dev <veth-host> ingress bpf da obj gvm_tc_filter.o sec tc

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// These are populated at load time by the Rust loader via map rewriting.
// Default values are placeholders — the loader MUST override them.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} gvm_config SEC(".maps");

// Config map keys
#define CFG_PROXY_IP    0   // Network byte order (big-endian)
#define CFG_PROXY_PORT  1   // Host byte order (converted at check time)

SEC("tc")
int gvm_egress_filter(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;

    // Allow ARP (required for veth L2 resolution)
    if (eth->h_proto == bpf_htons(ETH_P_ARP))
        return TC_ACT_OK;

    // Only process IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_SHOT;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_SHOT;

    // Read config from BPF map
    __u32 key_ip   = CFG_PROXY_IP;
    __u32 key_port = CFG_PROXY_PORT;
    __u32 *proxy_ip_ptr   = bpf_map_lookup_elem(&gvm_config, &key_ip);
    __u32 *proxy_port_ptr = bpf_map_lookup_elem(&gvm_config, &key_port);

    if (!proxy_ip_ptr || !proxy_port_ptr)
        return TC_ACT_SHOT; // Fail-closed: no config → drop

    __u32 proxy_ip   = *proxy_ip_ptr;
    __u16 proxy_port = (__u16)*proxy_port_ptr;

    // TCP → only allow to proxy IP:port
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_SHOT;

        if (ip->daddr == proxy_ip && tcp->dest == bpf_htons(proxy_port))
            return TC_ACT_OK;

        return TC_ACT_SHOT;
    }

    // UDP → only allow DNS (port 53) to proxy IP
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_SHOT;

        if (ip->daddr == proxy_ip && udp->dest == bpf_htons(53))
            return TC_ACT_OK;

        return TC_ACT_SHOT;
    }

    // ICMP and everything else: drop
    return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "Apache-2.0";
