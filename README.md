# NeTracker
Written by: Raihan Sultan

## Overview
A Network Traffic Tracker, working in kernel-level. Made using eBPF (C-Language), to practice myself with it.

NeTracker eBPF Program is built using C language, and also it has its BCC Loader with Python language.

For development versions, please visit [/netracker_test](https://github.com/raihansltn/netracker_test)
## Version-Explained

There are multiple versions of NeTracker here
- MainVer_BCC: NeTracker program using BCC Toolkit (Still on going, I'm still having a lot of troubles with the header)
- V2_EunomiaVer: NeTracker program made using eunomia-bpf toolkit, simpler, consists TC and XDP contexts.
- V2_BCCVer: NeTracker program, roughly the BCC-version "translation" of V2_EunomiaVer.

## Contexts Used
Below is a list of contexts used in this project.
- [BPF Compiler Collection (BCC)](https://github.com/iovisor/bcc) - Toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools.
- [Eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf) - a dynamic loading library/runtime and a compile toolchain framework, aim at helping you build and distribute eBPF programs easier.
- [Clang/LLVM](https://clang.llvm.org/) - Compile eBPF bytecode from C to BPF format
- [bpftool](https://bpftool.dev/) - Inspect and debug eBPF programs.
- [ecli](https://eunomia.dev/eunomia-bpf/ecli/) - To run ebpf programs as json or wasm.
- [eunomia-cc (ecc)](https://eunomia.dev/eunomia-bpf/ecc/) - To compile and package ebpf programs.
- [Kprobe / Tracepoints](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/1-helloworld#tracepoints) - Kernel function used to monitors outgoing TCP Connection, here I used tcp_v4 and tcp_v6 connect. Also inet_csk_accept to monitor incoming TCP connection. And Tracepoint sock:inet_sock_set_state to track TCP state transitions.
- [XDP (eXpress Data Path)](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/21-xdp) - Used to inspect packets before they reach the kernel stack.
- [TC (Traffic Control)](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/20-tc) - Used as Hooks at the network queuing layer for visibility on packets

## Features

- Monitor incoming connection, Port, IP, and Time Spend.

## Usage

- V2_EunomiaVer
```bash
cd NeTracker; cd V2_EunomiaVer
sudo ./ecc NeTracker.bpf.c
sudo ./ecli run package.json
```

## Result
- V2_EunomiaVer
```bash
systemd-resolve-540     [000] ..s21 19790.567694: bpf_trace_printk: [XDP] IP Source: 127.0.0.53, Port Source:53 -> Destination: 127.0.0.1, IP Destination:37944, Packet Size: 223, Time Spent: 58 ns
systemd-resolve-540     [000] ..s2. 19790.567748: bpf_trace_printk: [TC] IP Source: 127.0.0.53, Port Source:53 -> Destination: 127.0.0.1, IP Destination:37944, Packet Size: 1, Time Spent: 65 ns
systemd-resolve-540     [000] ..s21 19790.574237: bpf_trace_printk: [XDP] IP Source: 127.0.0.53, Port Source:53 -> Destination: 127.0.0.1, IP Destination:37944, Packet Size: 267, Time Spent: 65 ns
systemd-resolve-540     [000] ..s2. 19790.574249: bpf_trace_printk: [TC] IP Source: 127.0.0.53, Port Source:53 -> Destination: 127.0.0.1, IP Destination:37944, Packet Size: 1, Time Spent: 40 ns
           code-10438   [000] ..s21 19811.634624: bpf_trace_printk: [XDP] IP Source: 127.0.0.1, Port Source:41199 -> Destination: 127.0.0.53, IP Destination:53, Packet Size: 103, Time Spent: 68 ns
           code-10438   [000] ..s2. 19811.634657: bpf_trace_printk: [TC] IP Source: 127.0.0.1, Port Source:41199 -> Destination: 127.0.0.53, IP Destination:53, Packet Size: 64, Time Spent: 42 ns
           code-10438   [000] ..s21 19811.636938: bpf_trace_printk: [XDP] IP Source: 127.0.0.1, Port Source:41199 -> Destination: 127.0.0.53, IP Destination:53, Packet Size: 103, Time Spent: 53 ns
           code-10438   [000] ..s2. 19811.636962: bpf_trace_printk: [TC] IP Source: 127.0.0.1, Port Source:41199 -> Destination: 127.0.0.53, IP Destination:53, Packet Size: 64, Time Spent: 46 ns
systemd-resolve-540     [000] ..s21 19811.653038: bpf_trace_printk: [XDP] IP Source: 127.0.0.53, Port Source:53 -> Destination: 127.0.0.1, IP Destination:41199, Packet Size: 223, Time Spent: 53 ns
systemd-resolve-540     [000] ..s2. 19811.653064: bpf_trace_printk: [TC] IP Source: 127.0.0.53, Port Source:53 -> Destination: 127.0.0.1, IP Destination:41199, Packet Size: 1, Time Spent: 40 ns
systemd-resolve-540     [000] ..s21 19811.690148: bpf_trace_printk: [XDP] IP Source: 127.0.0.53, Port Source:53 -> Destination: 127.0.0.1, IP Destination:41199, Packet Size: 267, Time Spent: 44 ns
systemd-resolve-540     [000] ..s2. 19811.690162: bpf_trace_printk: [TC] IP Source: 127.0.0.53, Port Source:53 -> Destination: 127.0.0.1, IP Destination:41199, Packet Size: 1, Time Spent: 47 ns

```

##### This is an ongoing project.
Update Notes:
- Initial Commit - March 17th, 2025: To monitor every incoming connection, what port, what ip, and spend how many miliseconds? (How to map time in kprobe? how to make any difference on what are you currently tracking?)
- V1.2 - March 22nd, 2025: Push multiple versions of NeTracker
