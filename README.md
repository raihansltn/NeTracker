# NeTracker
Written by: Raihan Sultan Pasha Basuki

## Overview
A network traffic tracker that operates at the kernel level. It is implemented using eBPF with C. NeTracker uses the four-tuple of 5-tuple as the key, which is stored in conn_map. The key, captured during SYN packet capture in the Ingress TC filter, is then used to capture the FIN-ACK packet in the Egress TC filter, thus measuring the duration of a full connection.

NeTracker eBPF Program is built using C language, and also it has its BCC Loader with Python language.

## Version-Explained

There are multiple versions of NeTracker here
- EunomiaVer: NeTracker program made using eunomia-bpf toolkit, simpler, consists TC context.
- BCCVer: NeTracker program, roughly the BCC-version "translation" of EunomiaVer.

## Contexts Used
Below is a list of contexts used in this project.
- [BPF Compiler Collection (BCC)](https://github.com/iovisor/bcc) - Toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools.
- [Eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf) - a dynamic loading library/runtime and a compile toolchain framework, aim at helping you build and distribute eBPF programs easier.
- [Clang/LLVM](https://clang.llvm.org/) - Compile eBPF bytecode from C to BPF format
- [bpftool](https://bpftool.dev/) - Inspect and debug eBPF programs.
- [ecli](https://eunomia.dev/eunomia-bpf/ecli/) - To run ebpf programs as json or wasm.
- [eunomia-cc (ecc)](https://eunomia.dev/eunomia-bpf/ecc/) - To compile and package ebpf programs.
- [Kprobe / Tracepoints](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/1-helloworld#tracepoints) - Kernel function used to monitors outgoing TCP Connection, here I used tcp_v4 and tcp_v6 connect. Also inet_csk_accept to monitor incoming TCP connection. And Tracepoint sock:inet_sock_set_state to track TCP state transitions.
- [TC (Traffic Control)](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/20-tc) - Used as Hooks at the network queuing layer for visibility on packets
- [5-Tuple](https://www.ietf.org/rfc/rfc6146.txt#:~:text=5%2DTuple:%20The%20tuple%20(,and%20one%20with%20IPv6%20addresses.) - A five-tuple, also known as a quintuple, is a data structure in computing that consists of an ordered collection of five elements, often used in networking and cybersecurity. It's particularly relevant for identifying network connections and flows. 

## Features

- Monitor incoming connection, Port of both sources and destination, IP of both sources and destination, and Time elapsed.

## Usage

- First thing first, clone this repository to your destined path:
```bash
git clone https://github.com/raihansltn/NeTracker.git
```

- Install the requirements:
```bash
cd NeTracker
pip install -r requirements.txt
```

- EunomiaVer
1. Compile and deploy the program first, by running the script.
    ```bash
    cd EunomiaVer
    chmod +x netracker_reload.sh
    ./netracker_reload.sh
    ```
2. Open the log.
    ```bash
    sudo bpftool tracelog
    ```
    or if you don't have bpftool installed
    ```bash
    sudo cat /sys/kernel/debug/tracing/trace_pipe
    ```

- BCCVer (Untested)
1. Run the Python Script
    ```bash
    user@device:~/NeTracker$ cd BCCVer
    user@device:~/NeTracker/BCCVer$ sudo python3 NeTracker.py
    ```

## Result
- EunomiaVer
```bash
user@device:~/NeTracker/EunomiaVer$ sudo bpftool prog tracelog
         python3-5063    [001] b..1.  1137.507416: bpf_trace_printk: [TC] Total RTT (SYN - FIN-ACK) for 192.168.1.9:14599 -> 192.168.1.13:8000: 9556219 ns

         python3-5063    [001] b..1.  1140.787522: bpf_trace_printk: [TC] Total RTT (SYN - FIN-ACK) for 192.168.1.9:14602 -> 192.168.1.13:8000: 7173342 ns

         python3-5063    [001] b..1.  1145.453647: bpf_trace_printk: [TC] Total RTT (SYN - FIN-ACK) for 192.168.1.9:14605 -> 192.168.1.13:8000: 8297647 ns

         python3-5063    [001] b..1.  1147.334174: bpf_trace_printk: [TC] Total RTT (SYN - FIN-ACK) for 192.168.1.9:14607 -> 192.168.1.13:8000: 5482384 ns

         python3-5063    [000] b..1.  1150.723790: bpf_trace_printk: [TC] Total RTT (SYN - FIN-ACK) for 192.168.1.9:14609 -> 192.168.1.13:8000: 36651078 ns

         python3-5063    [000] b..1.  1153.420673: bpf_trace_printk: [TC] Total RTT (SYN - FIN-ACK) for 192.168.1.9:14611 -> 192.168.1.13:8000: 9438282 ns

         python3-5063    [000] b..1.  1156.369347: bpf_trace_printk: [TC] Total RTT (SYN - FIN-ACK) for 192.168.1.9:14614 -> 192.168.1.13:8000: 9952371 ns
```

- BCCVer
```Bash
user@device:~/NeTracker/BCCVer$ sudo python3 NeTracker.py
[TC] Total RTT (SYN - FIN-ACK) for 192.168.1.100:80 -> 192.168.1.200:443: 250000 ns
[TC] Total RTT (SYN - FIN-ACK) for 10.0.0.5:22 -> 10.0.0.10:5000: 1800000 ns
[TC] Total RTT (SYN - FIN-ACK) for 192.168.1.105:53 -> 192.168.1.1:53: 30000 ns
```

##### This is an ongoing project.
Update Notes:
- Initial Commit - March 17th, 2025: To monitor every incoming connection, what port, what ip, and spend how many miliseconds? (How to map time in kprobe? how to make any difference on what are you currently tracking?)
- V1.2 - March 22nd, 2025: Push multiple versions of NeTracker
- V1.3 - May 5th, 2025: Delete main ver, finish up the program, push Eunomia and BCC versions