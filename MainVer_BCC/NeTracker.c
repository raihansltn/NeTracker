#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

//this where I define the data structure that will be used to store the connection information
struct data_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u64 start_time;
};

//defining the map that will be used to store the connection information
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct data_t);
} connections SEC(".maps");

//this is the function that will handle the connection establishment
//it will be called when a connection is established
SEC("kprobe/tcp_v4_connect")
int trace_connect(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid();
    struct data_t data = {};
    
    bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&data.sport, sizeof(data.sport), &sk->__sk_common.skc_num);
    u16 dport;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    data.dport = bpf_ntohs(dport);

    data.pid = pid;
    data.start_time = bpf_ktime_get_ns();

    bpf_map_update_elem(&connections, &pid, &data, BPF_ANY);

    bpf_trace_printk("Connect: PID=%d SADDR=%pI4 DADDR=%pI4 SPORT=%d DPORT=%d\\n",
                     data.pid, &data.saddr, &data.daddr, data.sport, data.dport);

    return 0;
    }

//this is the hook into function that handles connection close
SEC("kprobe/tcp_close")
int trace_close(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid();
    struct data_t *data = bpf_map_lookup_elem(&connections, &pid);

    if (data) {
        u64 duration = bpf_ktime_get_ns() - data->start_time;
        
        //this is to print connection duration in kernel trace
        bpf_trace_printk("Close: PID=%d SADDR=%d DADDR=%d SPORT=%d DPORT=%d Duration=%llu ns\\n", 
                         data->pid, data->saddr, data->daddr, data->sport, data->dport, duration);

        bpf_map_delete_elem(&connections, &pid);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";