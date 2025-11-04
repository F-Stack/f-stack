# F-Stack Release Note

 F-Stack is an open source network framework based on DPDK.

## 2025.11 F-Stack v1.21.6(LTS)

1. F-Stack lib:

- Support bind no port like linux's IP_BIND_ADDRESS_NO_PORT.
- Add inner IP and port-based flow steering capabilities for the IPIP protocol.(Authors: Zhiwen Wang @hirowang1, Huiqin Zhang).
- Modify usleep to rte_delay_us_sleep.
- Add viritio support for kni.
- Build netgraph and ipfw by default.
- Disable RSS if hardware does not support it. @Clcanny
- ff_traffic support rx_dropped and tx_dropped.
- Added the -Wextra compilation option and fixed compilation errors.
- Add ff_log mod, that encapsulates some interfaces of the rte_log module.
- set the IP-type flag for tx_csum_l4 offload. @zcjie1
- Add ff_stop_run to stop the poll loop. @renzibei
- Add some cleanup action, however, it is incomplete.
- Add the feature fo ff_rss_check table to improve the performance of ff_rss_check(). See https://github.com/F-Stack/f-stack/wiki/%E2%80%8B%E2%80%8BF%E2%80%90Stack-ff_rss_check()-Optimization-Introduction%E2%80%8B

1. FreeBSD

- Add the feature fo ff_rss_check table to improve the performance of ff_rss_check(). See https://github.com/F-Stack/f-stack/wiki/%E2%80%8B%E2%80%8BF%E2%80%90Stack-ff_rss_check()-Optimization-Introduction%E2%80%8B

1. ff toos

- ff_traffic support rx_dropped and tx_dropped.

1. DPDK

- Modify real_if_indextoname return value and type. @giannisli

1. APP

- Nginx: Adapt nginx-1.28.0 to f-stack. @jinliu777



2024.10 F-Stack v1.21.5(LTS)

1. F-Stack lib:

- Modify ff_port_cfg.port_id's type from uint8_t to unint16_t.
- Modify INI_MAX_LINE from 200 to 2048 in lib/ff_ini_parser.h.
- IPv6 addr and vaddr set autoconf by default.
- Modify IPv4 vip addrs' broadaddr from x.x.x.255 to x.x.x.x, same as vip addr, because vips' netmask only support `255.255.255.255` now.
- Add APi ff_dpdk_raw_packet_send to suppoort RAW packet send direty with DPDK by user APP not via socket.
- Support automatic configuration of vlan and vlan ip, routing and the simplest policy routing.
- Use soclose() instead of sofree() when initializing the configuration stack IP.
- Support KNI ratelimit, default disable.
- The msghdr.msg_iov->iov_base and msghdr.msg_iov->iov_len of ff_sendmsg() and ff_recvmsg() compatible with the Linux.

1. FreeBSD

- Fix issue in Freebsd when building with GCC 14.1.0. @bjosv

1. ff toos

- Fix ff tools build error with gcc-13.2.0.

1. DPDK

- Fix some build errors of dpdk-19.11.14 with gcc-13.2.0.

1. APP

- Nginx: Nginx's stream support transparent.

1. doc

- Update ff tools README.md, use `ff_netstat -rnW` to display wider device name.
- Fix a typo in doc/F-Stack_Nginx_APP_Guide.md: "kernel_network_stack" -> "proxy_kernel_network_stack".



2023.10 F-Stack v1.21.4(LTS)

  1. F-Stack lib:

  - Add vlan_filter argument in config.ini for RSS with vlan.
    - Set Rx VLAN filter, and then the dirvier(such as MLX5) will set FLOW RSS to enable L3/L4 RSS below vlan hdr. This action won't need after DPDK-20.11.
  - Fix Compile Error with gcc 12.2.0.
  - gettimeofday automatically compatible with different glibc versions.
  - Add an API ff_get_traffic to get traffic for QoS or other.

  2. ff tools:

  - Fix Compile Error with gcc 12.2.0.

  3. APP:

  - gettimeofday automatically compatible with different glibc versions.



2023.09 F-Stack v1.21.3(LTS)

  1. F-Stack lib, Sync some features from branch of dev:

  - vlan_strip support kni.
  - Fix Compile Error with gcc 11.3.0(in Ubuntu 22.04).
  - Added F-Stack FreeBSD support. see 9f7a142 .
  - Enable INET6 by default in helloworld. see 51c91ab .
  - Added FDIR support. see 4854315 .
  - To avoid compiling errors when gcc version >= 10. see 6daadb0 .
  - Modify `struct linux_sockaddr` same to `struct sockaddr` in linux. see d96a9d1 .
  - Sync some modified of ff_config.c, inclue set dpdk log level, Avoid memory leaks, suppor vip_addr and vip_addr6, etc. see git log lib/ff_config.c in branch of dev.
  - Sync some modified of ff_syscall_wrapper.c, include ff_sendmsg, ff_recvmsg, ip6_opt_convert, etc. see git log lib/ff_syscall_wrapper.c in branch of dev.
  - The CPU usage of packet_dispatcher() is modified to usr. see 0508c8b .
  - If process_dispatch_ring() has data packet to be processed and it is considered non-idle state. see 81dd6c7 .
  - Fix a plurality of packets may not statistics in ff_traffic.rx_packets and ff_traffic.rx_bytes. see 0b4a084 .
  - Added FF_IPSEC=1 in lib/Makefile, disable by default.
  - Some other modified.

  2. DPDK:

  - DPDK: Upgrade to 19.11.14(LTS).

  3. APP:

  - Fiexd some build errors of micro_thread on ubuntu 22.04.


2022.09 F-Stack v1.21.2(LTS)

 1. F-Stack lib:

  - Fix #643. Fix a VXLAN issue. Thanks @agerguo
  - FF_USE_PAGE_ARRAY compatible DPDK 19.11.
  - Optimize random function in ff_compat.c @dingyuan
  - Enable net.inet.tcp.delayed_ack by default to improve concurrent performance.
  - Support zero copy while call `ff_write`, disable by default.
  - Fix the bonding issue. @Lorisy
  - Fix the issue that `ff_netstat -r` can't show gateway6.

 2. DPDK:

  - Upgrade to DPDK-19.11.13(LTS).



2021.09 F-Stack v1.21.1

 1. F-Stack lib:

  - lo port is added 127.0.0.1 when freebsd init.

 2. DPDK:

  - MLX5: modify if_indextoname syscall to support F-Stack tools.



2021.01 F-Stack v1.21

    1. F-Stack lib:
  - Fix use after free issue in mbuf free. #565 #556 @tanjianfeng @zouyonghao @freak82
  - Fix insufficient condition in ff_rte_frm_extcl function.
  - Fix wrong msg_flags in struct msghdr after calling ff_recvmsg in a Linux application.
  - Modify dump codes. @jinhao2
  - Feature knictl. @pengtianabc
  - Add configuration options `symmetric_rss` to set whether to use symmetric RSS.
  - Add IPv6 net addr parameters in config. @zengyi1001
  - Add `ff_regist_pcblddr_fun` to regist a pcb lddr function in F-Stack.
  - Config: Support parse "--file-prefix"&"--pci-whitelist" for multi-processes. @hawkxiang
  - Support rte_flow_isolate for multi lcore. @hawkxiang

  2. Nginx:

  - Fix some issues of nginx transparent proxy. @rolfliu

  3. micro_thread:

  - Add micro_thread_auto_adjust_thread_cnt. @WoolenWang
  - Fix compile error of micro_thread with gcc 8.3. @Xin Wang

  4. Tools:

  - Fix a crash bug while use `ff_ifconfig`.
  - Fix bug of `ff_sysctl`.
  - Fix some other bugs while use ff msg.
  - IPFW: supported IPv6. @zjwsoft
  - Add ff_ipc_exit() to clean temp files in /var/ while run F-Stack tools arp/ifconfig/route/ipfw. @zjwsoft
  - Add ndp tool for ipv6 neighbor. @chopin11


  5. DPDK:

  - Upgrade to 19.11.5 LTS.

  6. Others:

  - Update README.md. @soroshsabz



2019.11 F-Stack v1.20

  1. F-Stack lib:

  - Fix some bugs. Corresponding upstream changeset from Freebsd releng-11.0/release-11.1/release-11.2/release-11.3/release-12
  - Fix bug of bind and connect. @jin.hao
  - Fix F-stack compile error in Red Hat 8.0 with gcc 8.2.1.
  - Add IPv6 supported.
  - Add `make install`, and you can not must set `FF_DPDK` and `FF_PATH`.
  - Add `FF_USE_PAGE_ARRAY` compile switch in `Makefile`, turn on it will not use mcopy when transmit packetes from bsd to dpdk. @jin.hao
  - Add vlan supported. @dragonorloong
  - Add bonding suopported. *Note: some bond driver can not work with multi processes.*
  - Add `pkt_tx_delay` parameter in `config.ini`.
  - Add `tx_csum_offoad_skip` parameter in `config.ini`. @JayathS

  2. Nginx:

  - Upgrade to 1.16.1.

  3. Redis:

  - Upgrade to 5.0.5

  4. Tools:

  - Fix the crash bug while excute `ff_netstat -n`.
  - IPv6 supported.
  - Add `make install`, and you can use `ff_<tool_name>` to run F-Stack tools.
  - `ff_traffic` support `-P <max process id>` to show traffic info of all processes.
  - `ff_top` support `-P <max process id>` to show cpu usage of all processes.
  - All tools can work in one time.

  5. DPDK:

  - Upgrade to 18.11.5 LTS.

2019.11 F-Stack v1.13

  1. F-Stack lib:

  - Fix some bugs.
  - Add interface `ff_dup`, `ff_dup2``ff_ioctl_freebsd`, `ff_getsockopt_freebsd`, `ff_setsockopt_freebsd`.
  - Initial parameter `proc-type` can be NULL, default "auto".
  - Add "idle_sleep" parameter to reduce CPU usage when no pkts incomming, add `base_virtaddr` parameter for some vms.
  - Add arch arm64 compiler options.
  - Support Container(Docker).
  - Support vlan.

  2. Nginx:

  - Fix some bugs.
  - Hook `getpeername`,`getsockname`,`shutdown`.
  - Support "master_process off".

  3. Redis:

  - Reset cpu affinity when new process forked.

  4. Tools:

  - Add `traffic` tool.

  5. DPDK:

  - Upgrade to 17.11.4 LTS.

2018.5 F-Stack v1.12

  1. Fixed some bugs.
  2. Nginx: host event supported. 
  3. kern_timeout: decrease the cpu usage of timer.
  4. DPDK: upgrade to 17.11.2 LTS.

2017.11 F-Stack v1.11

  1. Intel DPDK network I/O module.
  2. FreeBSD Network Stack.
  3. Nic offload: checksum(IP/TCP/UDP), TSO, VLAN, etc.
  4. Network tools: sysctl, ifconfig, route, netstat, top, etc.
  5. Firewall supported: ipfw.
  6. Netgraph supported: ngctl.
  7. Posix-like API: socket,event.
  8. Coroutine API.
  9. Python bindings for F-Stack: pyfstack.
  10. App: Nginx/Redis supported.
