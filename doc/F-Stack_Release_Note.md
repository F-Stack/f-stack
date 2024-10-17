# F-Stack Release Note

 F-Stack is an open source network framework based on DPDK.

2024.10 F-Stack v1.24

1. F-Stack lib, Sync some features from branch of dev:

- Restore vEth0 to veth0 now.
- Add kni type argument in config.ini and FF_KNI_KNI in lib/Makefile to set exception path type.
- FF_FLOW_ISOLATE support DPDK-22.11.
- Add net.add_addr_allfibs=1 in config.ini.
- gettimeofday automatically compatible with different glibc versions.
- Add an API ff_get_traffic to get traffic for QoS or other.
- Add ff_stop_run to stop the poll loop. @renzibei
- Add POSIX Like functions for pthread_create and pthread_join. @Radu Nichita
- Fix pthread issue. @Vitaly Pavlov
- Fix a build error with gcc-4.8.5.
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

- Add atomic_fcmpset_int32.
- Fix some build errors of freebsd with gcc-12.2.0.
- For f-stack to support QAT accelerator cards. @wenchengji.
- Fix some build errors of freebsd with gcc-13.2.0.
- Fix issue in Freebsd when building with GCC 14.1.0. @bjosv

1. ff toos

- Fix ff tools build error with gcc-13.2.0.
- Fix netstat tool compilation on linux. Support `mawk` of ubuntu. @taras

1. DPDK

- DPDK: Upgrade to 22.11.6.
- Fix a compilation warning of drivers mlx5.
- Bump black from 22.10.0 to 24.3.0 in /dpdk/dts. @dependabot[bot]
- kni_net.c compatible with -Wstringop-overflow with different gcc versions.

1. APP

- Nginx: gettimeofday automatically compatible with different glibc versions.
- Nginx: Nginx's stream support transparent.

1. adapter

- syscall: Fix cplen calculation errors in ff_hook_syscall.c. @zhaozihanzzh
- syscall: Close kernel epoll fd in ff_hook_close when using FF_KERNEL_EVENT. @zhaozihanzzh

1. doc

- modify doc that re-enable kni now, to remove kni later.
- Modify nginx-1.16.1 to nginx-1.25.2 in docs.
- Remove doc/F-Stack_Binary_Release_Quick_Start.md.
- chore: update freebsd version in readme. @JamLee
- Update ff tools README.md, use `ff_netstat -rnW` to display wider device name.
- Update F-Stack_Quick_Start_Guide.md, add a cmd. @万能的翔王大人
- Fix a typo in doc/F-Stack_Nginx_APP_Guide.md: "kernel_network_stack" -> "proxy_kernel_network_stack".
-  Disable build driver crypto/openssl for Redhat/Centos 7.x.



2023.09 F-Stack v1.23

  1. F-Stack lib, Sync some features from branch of dev:

  - Added FDIR using general flow rules. @guhaoyu2005.
  - Added more clear error message in case of failed config read. @d06alexandrov.
  - vlan_strip support kni.
  - Removed deleted sources from Makefile. @d06alexandrov.
  - make it compilable under O2 optimization, pass gcc check. @renzibei.
  - enable -O2 by default. Ref #711 #721.
  - Fix #702 F-stack rack and BBR both causes PCB memory leak.
  - tcp: Missing mfree in rack and bbr.
  - when nginx use setsockopt ON_LINGER, the seq number of the RST packet is error. @wenchengji159357.
  - While use bbr, the hz should be set to 1000000, match the bintime and timer of F-Stack. Ref #701 #702.
  - Redis can listen IPv6 address.
  - Fix Compile Error with gcc 11.3.0(in Ubuntu 22.04). Close #736.
  - Fixed #705. While Adding -DNDEBUG flag will cause the helloworld example.
  - Add some description of `ff_socket()` and `ff_write()`. Ref #709.
  - Modify pci_whitelist to allow that from DPDK 20.11. Close #745.
  - fix that vtoslab doesn't return the correct slab. @zhutian.
  - When entering the softclock function for the first time,ticks is 2147423648,cc_softticks is 0. @wenchengji159357.
  - Add adapter for LD_PRELOAD. EXPERIMENTAL.
  - fix cmsg for sendmsg. @sarosh.
  - Fixed an issue that before C99 mode..
  - Fiexd some build errors of ipfw on ubuntu 22.04 (kernel:5.19.0-1025, gcc:11.4.0),
  - fix some issue of ff_sendmsg and ff_recvmsg.
  - Support LINUX_IP_TRANSPARENT and LINUX_IPV6_TRANSPARENT to IP_BINDANY and IPV6_BINDANY in lib/ff_syscall_wrapper.c.

  2. DPDK:

  - DPDK: Upgrade to 21.11.5.
  - Fix I40E_DEV_ID_10G_BASE_T_X722 issue.
  - Update igb_uio, sync from git://dpdk.org/dpdk-kmods.

  3. APP:

  - Nginx: Upgrade to Nginx-1.25.2 to support HTTP3. EXPERIMENTAL.
  - Add adapter for LD_PRELOAD. EXPERIMENTAL.
  - move /app/micro_thread to adapter/micro_thread.
  - Fix netmask in nginx conf. @jiegec.
  - Fiexd some build errors of micro_thread on ubuntu 22.04 (kernel:5.19.0-1025, gcc:11.4.0),

  4. example:

  - Set non blocking in example/main.c. Ref #709.
  - Add helloworld_stack_epoll、 main_stack_epoll_pipeline and kevent for LD_PRELOAD demo.
  - Fiexd some build errors of example on ubuntu 22.04 (kernel:5.19.0-1025, gcc:11.4.0).


2023.09 F-Stack v1.22.1

  1. F-Stack lib:

  - Fix #702 F-stack rack and BBR both causes PCB memory leak.
  - While use bbr, the hz should be set to 1000000, match the bintime and timer of F-Stack. Ref #701 #702
  - Modify pci_whitelist to allow that from DPDK 20.11. Close #745.

  2. DPDK:

  - Upgrade to DPDK-20.11.9(LTS).



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
