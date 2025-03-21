#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800  /* Internet Protocol packet */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

//eBPF hash map to store connection data (esp in this case, the key: source IP, value: timestamp)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} conn_map SEC(".maps");

/// @tchook {"ifindex":1, "attach_point":"BPF_TC_INGRESS"}
/// @tcopts {"handle":1, "priority":1}

//The next function is Traffic Control (TC) ingress hook function.
//so this function is triggered on incoming packets at the ingress point.
//It extracts IP and transport-layer information (TCP/UDP) and logs packet details.

//param ctx is BPF context representing packet data
//return TC_ACT_OK (pass the packet)
SEC("tc")
int tc_ingress(struct __sk_buff *ctx) {
    __u64 start_time = bpf_ktime_get_ns();  //we start the timer from here for TC timestamp

    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;
    struct tcphdr *tcp;
    struct udphdr *udp;

    //this to ensure the packet is an IPv4 packet
    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

    __u32 src_ip = bpf_ntohl(l3->saddr);
    __u32 dst_ip = bpf_ntohl(l3->daddr);
    __u16 src_port = 0, dst_port = 0;

    //extracting TCP/UDP and ports
    if (l3->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *)(l3 + 1);
        if ((void *)(tcp + 1) <= data_end) {
            src_port = bpf_ntohs(tcp->source);
            dst_port = bpf_ntohs(tcp->dest);
        }
    } else if (l3->protocol == IPPROTO_UDP) {
        udp = (struct udphdr *)(l3 + 1);
        if ((void *)(udp + 1) <= data_end) {
            src_port = bpf_ntohs(udp->source);
            dst_port = bpf_ntohs(udp->dest);
        }
    }

    __u64 end_time = bpf_ktime_get_ns(); //end the time for tc here
    __u64 elapsed_time = end_time - start_time;  //calc time spent

    //logging packet details
    bpf_printk("[TC] IP Source: %u.%u.%u.%u, Port Source:%d -> Destination: %u.%u.%u.%u, IP Destination:%d, Packet Size: %d, Time Spent: %llu ns",
               (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF, (src_ip >> 8) & 0xFF, src_ip & 0xFF,
               src_port,
               (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF, (dst_ip >> 8) & 0xFF, dst_ip & 0xFF,
               dst_port, l3->ttl, elapsed_time);

    return TC_ACT_OK;
}

/// @ifindex 1
/// @flags 0
/// @xdpopts {"old_prog_fd":0}

//the tc func ends here, now we move to eBPF XDP (Express Data Path) program for packet inspection and logging
//in this function, it processes packets at the earliest possible stage in the kernel networking stack

//parameter ctx is the XDP context containing packet metadata
//return XDP_PASS (allow packet processing)
SEC("xdp")
int xdp_pass(struct xdp_md* ctx) {
    __u64 start_time = bpf_ktime_get_ns();  //we start timer here

    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    struct ethhdr *l2;
    struct iphdr *l3;
    struct tcphdr *tcp;
    struct udphdr *udp;

    //this to ensure the packet is large enough to contain an Ethernet header
    if (data + sizeof(*l2) > data_end)
        return XDP_PASS;
    l2 = data;

    //checking if packet is an IPv4 packet
    if (l2->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = bpf_ntohl(l3->saddr);
    __u32 dst_ip = bpf_ntohl(l3->daddr);
    __u16 src_port = 0, dst_port = 0;

    //extract transport-layer protocol (TCP/UDP) and also ports
    if (l3->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *)(l3 + 1);
        if ((void *)(tcp + 1) <= data_end) {
            src_port = bpf_ntohs(tcp->source);
            dst_port = bpf_ntohs(tcp->dest);
        }
    } else if (l3->protocol == IPPROTO_UDP) {
        udp = (struct udphdr *)(l3 + 1);
        if ((void *)(udp + 1) <= data_end) {
            src_port = bpf_ntohs(udp->source);
            dst_port = bpf_ntohs(udp->dest);
        }
    }

    __u64 end_time = bpf_ktime_get_ns();
    __u64 elapsed_time = end_time - start_time; //this to calc time spent

    //loggin the packet details
    bpf_printk("[XDP] IP Source: %u.%u.%u.%u, Port Source:%d -> Destination: %u.%u.%u.%u, IP Destination:%d, Packet Size: %d, Time Spent: %llu ns",
               (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF, (src_ip >> 8) & 0xFF, src_ip & 0xFF,
               src_port,
               (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF, (dst_ip >> 8) & 0xFF, dst_ip & 0xFF,
               dst_port, data_end - data, elapsed_time);

    return XDP_PASS;
}

//license declaration
char __license[] SEC("license") = "GPL";