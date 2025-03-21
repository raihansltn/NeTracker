from bcc import BPF
import argparse
import os

# Define the eBPF program file
EBPF_PROGRAM_FILE = "NeTracker.c"

def get_interface():
    """Finds the default network interface"""
    with os.popen("ip route | grep default") as f:
        return f.read().split()[4]

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Attach eBPF XDP program to an interface")
parser.add_argument("-i", "--interface", type=str, default=get_interface(),
                    help="Network interface to attach (default: detected interface)")

args = parser.parse_args()
iface = args.interface

# Load and attach the eBPF program
print(f"Loading eBPF program on interface: {iface}")
bpf = BPF(src_file=EBPF_PROGRAM_FILE)
fn = bpf.load_func("xdp_prog", BPF.XDP)

# Attach the program to XDP
bpf.attach_xdp(iface, fn, 0)

print("eBPF XDP program successfully attached. Monitoring packets...")
print("Press Ctrl+C to stop.")

# Read output logs from bpf_trace_printk
try:
    while True:
        (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
        print(f"[{ts:.2f}] {msg}")
except KeyboardInterrupt:
    print("\nDetaching eBPF program...")
    bpf.remove_xdp(iface, 0)
    print("NeTracker detached successfully!")