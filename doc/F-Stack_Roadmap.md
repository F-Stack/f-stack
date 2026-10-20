# F-Stack Roadmap

This list are major known features, and obviously neither complete nor guaranteed.

1. FreeBSD-15.0 support.
   - FreeBSD-15.0 release : December 2025
   - F-Stack updata to FreeBSD-15.0 : Before April 30, 2026
   - F-Stack release 1.26 : October 2026
2. DPDK-24.11 support.
3. Redis-8 support.



Previously expired Roadmap.

1. ~~Interrupt mode support.~~
   - The minimum timeout unit for epoll_wati in interrupt mode is 1ms, which is not suitable for F-Stack and is therefore abandoned.
   - You can config idle_sleep to instead of interrupt mode, and the difference in effect is very small.
2. Run as a network daemon. done.
   - Alread support >= F-Stack-1.23.
3. ~~SPDK supportted.~~
4. Encapsulate Cyptodev API(Intel QAT). done.
   - Alread support >= F-Stack-1.24‘s Nginx, bug you need merge yourself [QAT's pr](https://github.com/intel/QAT_Engine/pull/316).
5. HTTP3(QUIC) support. done.
   - Alread support >= F-Stack-1.23's Nginx.

