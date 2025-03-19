from bcc import BPF
from time import sleep

#this where I load eBPF program
bpf = BPF(src_file="NeTracker.c")

#this is where I attach the eBPF program to the kernel
bpf.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")
bpf.attach_kprove(event="tcp_close", fn_name="trace_close")

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