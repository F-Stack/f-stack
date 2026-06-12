# 20 · Implementation Execution Plan (FSTACK_ZC_RECV)

> Based on spec 10-19. This phase begins writing the implementation code. All changes are gated by `#ifdef FSTACK_ZC_RECV`, disabled by default → zero impact on the existing build.
> Iron rule: every step is actually compile-verified; changes follow the spec as a blueprint but defer to the actual code/compilation results.

## Execution Order (M0→M1→M2, M3-M5 to follow)
| Step | Milestone | Files Changed | Exit Condition |
|---|---|---|---|
| 1 | Build baseline | —— | Confirm lib currently compiles (or record the status quo) |
| 2 | M0-kernel | freebsd/kern/uipc_syscalls.c (+ declaration) | kern_zc_recvit compiles |
| 3 | Switch | lib/Makefile | FF_ZC_RECV→FSTACK_ZC_RECV |
| 4 | M1-API declarations | lib/ff_api.h | ff_zc_recv/ff_zc_recv_free/ff_zc_mbuf_read declarations |
| 5 | M1-userspace | lib/ff_syscall_wrapper.c (ff_zc_recv), lib/ff_veth.c (read rewrite + free) | compiles |
| 6 | Build verification | —— | FSTACK_ZC_RECV=1 compiles; default build does not regress |
| 7 | M2/tests | tests/ | to follow |

## Anti-regression
- All newly added code is `#ifdef FSTACK_ZC_RECV`;
- Do not change the soreceive core, do not change the original kern_recvit/soo_read;
- Default build (FF_ZC_RECV undefined) is identical to before the changes.
