# F-Stack Release Note

 F-Stack is an open source network framework based on DPDK.

2022.09 F-Stack v1.22

  1. Freebsd

  - Upgrade to FreeBSD-releng-13.0,  support RACK and BBR.

  1. F-Stack lib:

  - Support extra tcp stacks, RACK and BBR. Significantly improves the performance of large file transfer(more than 10 times) in high latency and packet loss scenarios. Thanks @FireAngell.
  - F-Stack support HPTS for RACK and BBR.
  - lo port is added 127.0.0.1 when freebsd init.
  - Fix #643. Fix a VXLAN issue. Thanks @agerguo
  - FF_USE_PAGE_ARRAY compatible DPDK 19.11.
  - Optimize random function in ff_compat.c @dingyuan
  - Enable net.inet.tcp.delayed_ack by default to improve concurrent performance.
  - Support zero copy while call `ff_write`, disable by default.
  - Fix the bonding issue. @Lorisy @agerguo
  - Fix the issue that `ff_netstat -r` can't show gateway6.
  - Fix compile error of micro_thread with gcc 8.3. @Xin Wang
  - to avoid compiling errors when gcc version >= 10. @ZZMarquis
  - Support FDIR. @hawkxiang
  - fix use after free issue in mbuf free. @Jianfeng Tan
  - Fix #568, Insufficient condition in ff_rte_frm_extcl function. @freak82
  - Add IPv6 net addr parameters in config. @zengyi1001
  - Add ff_regist_pcblddr_fun to regist a pcb lddr function in F-Stack to select source IP when as client.
  - modify struct linux_sockaddr same to struct sockaddr in linux.
  - Support IPPROTO_IPV6's `IPV6_V6ONLY` and `IPV6_RECVPKTINFO`. @hawkxiang
  - Support set multi virtual IPv4/IPv6 net addrs in config.ini.
  - Add support for multiple pci_whitelist in config.ini. @ibtisam-tariq
  - Add support to set interface name of each port in config.ini. @ibtisam-tariq
  - ff_syscall_wrapper.c: add linux_cmsghdr and its support in recvmsg add support for `IP_RECVTTL` and `IP_RECVTOS`. @FidaullahNoonari-emumba
  - Added F-Stack FreeBSD 13.0 support. @guhaoyu2005
  - Add IP_MINTTL flag in ff_syscall_wrapper.c. @FidaullahNoonari-emumba
  - alows user to set dpdk log level from config.ini file. @Jawad-Hussain-23
  - Fix ff_syscall_wrapper.c: in ff_recvfrom() in case of zero *fromlen, *from will not be filled with garbadge values. @Sarosh Arif

  2. DPDK:

  - Upgrade to DPDK-20.11.6(LTS).
  - MLX5: modify if_indextoname syscall to support F-Stack tools.

  3. ff tools

- Fix bug of ff_ipc_msg_free in ff tools.
- The ff_traffic and ff_top's -P argument support bigger than 38.


  4. APP

- Redis: Upgrade to Redis-6.2.6. @GlareR

  5. example

- Enable INET6 by default in helloworld.



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

  - Upgrade to 19.11.6 LTS.

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
