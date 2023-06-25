# netatop-bpf
Created/maintained by liuting
## Introduction
The Linux kernel does not maintain counters for the number of network accesses issued per process. As a consequence, it is not possible to analyze which process causes most load in case that atop shows a high utilization on one of your network interfaces.(For performance reasons, threads are not counted.)

The optional netatop-bpf can be loaded to gather statistics about the TCP and UDP packets that have been transmitted/received per process. As soon as atop discovers that netatop-bpf is active, it shows the columns SNET and RNET in the generic screen for the number of transmitted and received packets per process. When the 'n' key is pressed, it shows detailed counters about the number packets transmitted/received via TCP and UDP, the average sizes of these packets, and the total bandwidth consumed for input and output per process/thread.

The bpf program hooks the transport layer of the network Protocol Stack to count information in the map when sending and receiving data packets. The hook function is the tracepoint merged in kernel 6.3. When a network event occurs and it is TCP/UDP protocol, it will reach the function processing of the transport layer, and the function registered on the hook point will be triggered. The main function is to maintain statistics on the network traffic of per process in the map. 
  - Kernel (>= 6.3) merged tracepoint:
    - tracepoint/sock/sock_sendmsg_length
    - tracepoint/sock/sock_recvmsg_length

Netatop runs normally and it has two functions. One is responsible for loading the bpf program to the kernel and communicating with the bpf program through the bpf map; the other is to communicate with atop through the Unix Domain Socket.

Atop send to netatop every interval(default 10s), netatop recv from atop and then traverses the bpf map sending all process information to atop, atop uses the hash table to store the information of all processes, and then traverses the /proc file (exits the process) to obtain the pid of the process and find the hashmap.


## How to use
```
// netatop-bpf
git clone --recurse-submodules https://github.com/bytedance/netatop-bpf.git 
cd netatop-bpf; make & make install

// atop
git clone  https://github.com/bytedance/atop.git -b netatop-bpf
cd atop; make & make install
```
