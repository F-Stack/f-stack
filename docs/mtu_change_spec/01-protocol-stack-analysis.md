# Protocol-Stack Layer Analysis: SIOCSIFMTU Full Path

> This document analyzes f-stack's user-space FreeBSD protocol stack handling of MTU modification (`SIOCSIFMTU`/`SIOCGIFMTU`). All references are actual code `file:line`.

## 1. Application Layer → f-stack ioctl Conversion

f-stack exposes Linux-semantics `ff_ioctl`, which must convert Linux `SIOCSIFMTU`/`SIOCGIFMTU` to FreeBSD equivalents.

`lib/ff_syscall_wrapper.c`:
```c
177: #define LINUX_SIOCGIFMTU      0x8921
178: #define LINUX_SIOCSIFMTU      0x8922
...
518:        case LINUX_SIOCGIFMTU:
519:            return SIOCGIFMTU;
520:        case LINUX_SIOCSIFMTU:
521:            return SIOCSIFMTU;
```

- Read MTU: `LINUX_SIOCGIFMTU(0x8921)` → FreeBSD `SIOCGIFMTU`
- Set MTU: `LINUX_SIOCSIFMTU(0x8922)` → FreeBSD `SIOCSIFMTU`

The protocol-stack layer **does have** the conversion path to receive MTU modification requests; `tools/sbin/ifconfig` also changes MTU through this path.

## 2. Generic ifioctl Layer (if.c)

The converted `SIOCSIFMTU` enters FreeBSD's generic interface ioctl dispatch.

`freebsd/net/if.c`:
```c
2729:  case SIOCSIFMTU:
2733:      error = priv_check(td, PRIV_NET_SETIFMTU);   // permission check
2736:      if (ifr->ifr_mtu < IF_MINMTU || ifr->ifr_mtu > IF_MAXMTU)  // broad bounds
              ... (out-of-range EINVAL)
          // call driver's if_ioctl callback
2755:          if_notifymtu(ifp);   // notify MTU change on success and change
```
Read MTU:
```c
2515:      ifr->ifr_mtu = ifp->if_mtu;   // SIOCGIFMTU returns software value
```

- The `if.c` layer only does `priv_check` and **broad** bounds checking (`IF_MINMTU`~`IF_MAXMTU`, `IF_MAXMTU` up to 65535) — not the source of the 1500 limit.
- After passing `priv_check`/bounds, it calls the driver's `if_ioctl` callback (i.e., `ff_veth_ioctl`).

## 3. Driver Layer ff_veth_ioctl (Key Delegation Point)

`lib/ff_veth.c`:
```c
234: static int
235: ff_veth_ioctl(if_t ifp, u_long cmd, caddr_t data)
236: {
238:     struct ff_veth_softc *sc = if_getsoftc(ifp);
240:     switch (cmd) {
241:     case SIOCSIFFLAGS:            // only explicitly handles UP/DOWN
242:         if (if_getflags(ifp) & IFF_UP) { ff_veth_init(sc); }
244:         else if (...) ff_veth_stop(sc);
246:         break;
247:     default:
248:         error = ether_ioctl(ifp, cmd, data);   // SIOCSIFMTU falls here
249:         break;
250:     }
252:     return (error);
253: }
```

Callback registration (`ff_veth_setup_interface`):
```c
923:     if_setioctlfn(ifp, ff_veth_ioctl);
```

- `ff_veth_ioctl` **does not handle `SIOCSIFMTU` separately**; it delegates entirely to FreeBSD's generic Ethernet handler `ether_ioctl`.
- This means: **f-stack has no DPDK hardware propagation hook for MTU modification at the driver layer** (no `rte_eth_dev_set_mtu` call).

## 4. ether_ioctl's 1500 Hard Upper Bound (True Source of EINVAL)

`freebsd/net/if_ethersubr.c`:
```c
1174:  case SIOCSIFMTU:
1178:      if (ifr->ifr_mtu > ETHERMTU) {
1179:          error = EINVAL;              // >1500 rejected directly
1181:      } else ifp->if_mtu = ifr->ifr_mtu;   // ≤1500 writes software value
```

- `ETHERMTU = 1500`. This is the **true upper bound source for MTU modification**:
  - `ifr_mtu ≤ 1500`: accepted, writes `ifp->if_mtu` (software value).
  - `ifr_mtu > 1500`: returns `EINVAL`, `if_mtu` unchanged.

## 5. MTU Initial Value

`ether_ifattach` statically initializes MTU to 1500 on NIC attach:
```c
985:      ifp->if_mtu = ETHERMTU;
```
`ff_veth_setup_interface` (`ff_veth.c:927`) calls `ether_ifattach(ifp, sc->mac)`, so the f-stack NIC defaults to MTU=1500.

## Summary (Protocol-Stack Layer)

- **Can change**: The protocol-stack layer supports modifying `if_mtu` software value via `ff_ioctl(SIOCSIFMTU)`, provided it is **≤1500**.
- **Cannot increase**: `ether_ioctl` hardcodes `> ETHERMTU(1500)` → `EINVAL`; f-stack does not intercept/override in `ff_veth_ioctl`, so jumbo is rejected at the protocol-stack layer.
- **No hardware propagation**: Regardless of success, the `if_mtu` software value is never propagated to the DPDK port via `rte_eth_dev_set_mtu` (see `02-dpdk-hardware-analysis.md`).
