#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/bpf.h>

SEC("xdp")
int xdp_prog(struct __sk_buff *ctx) {
    __u64 start_time = bpf_ktime_get_ns(); // Start timing

    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;

    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;

    // Ensure packet is large enough for an Ethernet header
    eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Ensure packet is IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Ensure packet is large enough for an IP header
    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // Extract Source & Destination IP
    __u32 src_ip = bpf_ntohl(ip->saddr);
    __u32 dst_ip = bpf_ntohl(ip->daddr);
    
    __u16 src_port = 0, dst_port = 0;

    // Extract TCP/UDP ports
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    }

    __u64 end_time = bpf_ktime_get_ns(); // End timing
    __u64 elapsed_time = end_time - start_time;

    // Log captured packet details
    bpf_trace_printk("NeTracker: IP %u.%u.%u.%u:%d -> %u.%u.%u.%u:%d TTL: %d Time: %llu ns\n",
        (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF, (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port,
        (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF, (dst_ip >> 8) & 0xFF, dst_ip & 0xFF, dst_port,
        ip->ttl, elapsed_time);

    return XDP_PASS;
}
