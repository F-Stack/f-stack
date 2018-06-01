# F-Stack Release Note

F-Stack is an open source network framework based on DPDK.

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
