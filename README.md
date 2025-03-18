# NeTracker
Written by: Raihan Sultan

## Overview
A Network Traffic Tracker, working in kernel-level. Made using eBPF (C-Language), to practice myself with it.

NeTracker eBPF Program is built using C language, and also it has its BCC Loader with Python language.

## Contexts Used
Below is a list of contexts used in this project.
- [BPF Compiler Collection (BCC)](https://github.com/iovisor/bcc) - Toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools.
- [Clang/LLVM](https://clang.llvm.org/) - Compile eBPF bytecode from C to BPF format
- [bpftool](https://bpftool.dev/) - Inspect and debug eBPF programs.
- [Kprobe / Tracepoints](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/1-helloworld#tracepoints) - Kernel function used to monitors outgoing TCP Connection, here I used tcp_v4 and tcp_v6 connect. Also inet_csk_accept to monitor incoming TCP connection. And Tracepoint sock:inet_sock_set_state to track TCP state transitions.
- [XDP (eXpress Data Path)](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/21-xdp) - Used to inspect packets before they reach the kernel stack.
- [TC (Traffic Control)](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/20-tc) - Used as Hooks at the network queuing layer for visibility on packets

## Features

- Monitor incoming connection, Port, IP, and Time Spend.

## Usage

##### This is an ongoing project.
Update Notes:
- Initial Commit - March 17th, 2025: To monitor every incoming connection, what port, what ip, and spend how many miliseconds? (How to map time in kprobe? how to make any difference on what are you currently tracking?)