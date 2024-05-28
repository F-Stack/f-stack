This directory stores some adapters based on the F-Stack lib library, currently includes `micro_thread` and `syscall`.

## micro_thread

Provides micro thread interface. Various applications with stateful applications can easily use F-Stack to get high performance without processing complex asynchronous logic.

## syscall

Hijack Linux kernel syscall with f-stack api, can use `LD_PRELOAD` to support existing applications, such as Nginx.

It also can support f-stack and kernel stack at the same time.

  