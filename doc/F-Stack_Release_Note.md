# F-Stack Release Note

 F-Stack is an open source network framework based on DPDK.

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
