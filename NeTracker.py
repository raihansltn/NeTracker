from bcc import BPF
from time import sleep
import socket
import struct

#this where I load eBPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
    u32 pid = bpf_get_current_pid_tgid();
    u32 saddr = sk->__sk_common.skc_rcv_saddr;
    u32 daddr = sk->__sk_common.skc_daddr;
    u16 sport = sk->__sk_common.skc_num;
    u16 dport = bpf_ntohs(sk->__sk_common.skc_dport);
    bpf_trace_printk("TCPv4 Connect: PID=%d SADDR=%d DADDR=%d SPORT=%d DPORT=%d\\n", 
                     pid, saddr, daddr, sport, dport);
    return 0;
}
int trace_close(struct pt_regs *ctx, struct sock *sk)
{
    u32 pid = bpf_get_current_pid_tgid();
    u32 saddr = sk->__sk_common.skc_rcv_saddr;
    u32 daddr = sk->__sk_common.skc_daddr;
    u16 sport = sk->__sk_common.skc_num;
    u16 dport = bpf_ntohs(sk->__sk_common.skc_dport);

    bpf_trace_printk("TCP Close: PID=%d SADDR=%d DADDR=%d SPORT=%d DPORT=%d\\n", 
                     pid, saddr, daddr, sport, dport);
    return 0;
}
"""

b = BPF(text=bpf_program)

#this is where I attach the eBPF program to the kernel
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")
b.attach_kprove(event="tcp_close", fn_name="trace_close")

#headers
print("%-6s %-12s %-16s %-16s %-6s %-6s" % ("PID", "COMM", "SADDR", "DADDR", "SPORT", "DPORT"))

#this to read and process data from eBPF map
while True:
    try:
        sleep(1)
        with open("/sys/kernel/debug/tracing/trace_pipe", "r") as f:
            for line in f:
                print(line.strip())
    except KeyboardInterrupt:
        print("\nStopping")
        break