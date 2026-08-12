# 00 — Investigation Overview

## Issue #1063 Details

- **Link**: https://github.com/F-Stack/f-stack/issues/1063
- **Type**: Feature enhancement request (not a bug)
- **Requirement**: Add UDP example under `adapter/syscall` directory

## Existing Examples

| File | Type | Linking |
|------|------|---------|
| `main_stack.c` | TCP (kqueue) | `-lff_syscall` |
| `main_stack_thread_socket.c` | TCP thread socket (kqueue) | `-lff_syscall` |
| `main_stack_epoll.c` | TCP epoll | LD_PRELOAD |
| `main_stack_epoll_thread_socket.c` | TCP epoll thread socket | LD_PRELOAD |
| `main_stack_epoll_kernel.c` | TCP epoll kernel event | LD_PRELOAD |

All existing examples are TCP; no UDP examples.

## UDP Syscall Hook Coverage Verification

Through code exploration, F-Stack's LD_PRELOAD mode (`libff_syscall.so`) provides complete hook coverage for UDP-related syscalls:

| Hook Function | File Location | Verification Result |
|---------------|---------------|---------------------|
| `fstack_territory()` | `ff_hook_syscall.c:360-374` | L368-369 explicitly accepts `SOCK_DGRAM` |
| `ff_hook_recvfrom()` | `ff_hook_syscall.c:909-910` | Complete implementation with `CHECK_FD_OWNERSHIP` dispatch |
| `ff_hook_sendto()` | `ff_hook_syscall.c:1613-1614` | Complete implementation with `CHECK_FD_OWNERSHIP` dispatch |
| `ff_hook_recvmsg()` | `ff_hook_syscall.c:1429` | Complete implementation |
| `ff_hook_sendmsg()` | `ff_hook_syscall.c:1683` | Complete implementation |
| `ff_hook_epoll_create()` | `ff_hook_syscall.c:1977` | Complete implementation |
| `ff_hook_epoll_ctl()` | `ff_hook_syscall.c:2009` | Complete implementation |
| `ff_hook_epoll_wait()` | `ff_hook_syscall.c:2090` | Complete implementation |

`sendto`, `recvfrom`, `sendmsg`, `recvmsg` are all declared in `ff_declare_syscalls.h:18-23`.

## Conclusion

F-Stack's LD_PRELOAD mode already fully supports all necessary syscalls for UDP sockets. Adding a UDP example requires no changes to the protocol stack library code — only writing an example program using standard POSIX APIs that transparently uses the F-Stack userspace network stack via LD_PRELOAD.
