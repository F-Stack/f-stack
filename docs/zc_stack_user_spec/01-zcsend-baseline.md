# 01 · ZC-SEND Baseline Reference Full Chain (FSTACK_ZC_SEND / M8)

> Probe: probe-zcsend (read-only measurement). All file:line:symbol references verified. Where code and comments conflict, code prevails.

## 0. One-Sentence Overview
APP `ff_zc_mbuf_get` allocates the BSD mbuf chain → `ff_zc_mbuf_write` uses `bcopy` to fill the mbuf trailing space → `ff_zc_send` treats the **mbuf chain head pointer** as `iov_base` and stamps the sentinel `FSTACK_ZC_MAGIC` into `uio_offset` → `kern_writev → dofilewrite` (offset=-1 preserves magic) → the kernel `m_uiotombuf` detects the magic → **directly treats iov_base as the mbuf chain and attaches it, skipping m_getm2 allocation and the uiomove copy**.
**Direction: user-space constructs the mbuf, the kernel takes over (user → kernel).**

## 1. API Layer
### 1.1 `struct ff_zc_mbuf` (ff_api.h:347-352)
| Field | Meaning |
|---|---|
| `bsd_mbuf` | points to the **head** of the mbuf chain (the handle passed to the kernel) |
| `bsd_mbuf_off` | the mbuf at the current write position (locates continuation across multiple writes) |
| `off` | the accumulated written offset; the APP should not modify it (ff_api.h:350 comment) |
| `len` | total capacity of the chain allocated by get |

### 1.2 `ff_zc_mbuf_get` (ff_veth.c:306-323)
- `m_getm2(NULL, max(len,1), M_WAITOK, MT_DATA, 0)` (L313) allocates in one shot an mbuf chain able to hold len bytes;
- the 5th argument flags=0 → **no M_PKTHDR**;
- `bsd_mbuf=bsd_mbuf_off=mb; off=0; len=len` (L318-320); returns -1 on failure.

### 1.3 `ff_zc_mbuf_write` (ff_veth.c:325-356)
- continues writing from `bsd_mbuf_off`, traversing along m_next, writing `min(M_TRAILINGSPACE(mb), remaining)` per mbuf (L341);
- **still `bcopy` (L342)** —— what ZC saves is the "user→kernel" copy; filling the mbuf itself still copies once;
- only updates each mbuf's `m_len`, **does not update m_pkthdr.len** (L349-350 are commented out); the total length is reflected via ff_zc_send's nbytes through m_uiotombuf's total.

### 1.4 `ff_zc_mbuf_read` (ff_veth.c:358-363) = empty stub
`// DOTO: Support read zero copy; return 0;`. The signature `const char *data` does not match "read out" semantics; it is an undesigned placeholder.

## 2. User-Space syscall Layer
- `ff_zc_send` (ff_syscall_wrapper.c:1199-1225, `#ifdef FSTACK_ZC_SEND`): `aiov.iov_base=mb` (L1210), `auio.uio_offset=FSTACK_ZC_MAGIC` (L1216) → `kern_writev` (L1217).
- Mis-trigger guard: ordinary `ff_write` (L1151) / `ff_writev` (L1175) explicitly `uio_offset=0` opt-out (an uninitialized uio_offset on the stack auio would falsely trigger the magic, causing m_demote GPF; see L1146-1150 comment).

## 3. Kernel Hook Layer (freebsd/kern/uipc_mbuf.c)
- The `#ifdef FSTACK_ZC_SEND` branch of `m_uiotombuf` (L2028-2046): when `uio->uio_offset == FSTACK_ZC_MAGIC` (L2041) → directly attaches iov_base as the mbuf chain, skips the regular copy loop, and rewrites `uio->uio_offset` to `total` (L2046).
- Sentinel: `FSTACK_ZC_MAGIC ((off_t)0xF8AC2C00F8AC2C00LL)` (freebsd/sys/mbuf.h:1868).
- kern_writev → dofilewrite passes `offset=(off_t)-1`, not overwriting auio.uio_offset, so the magic is preserved until m_uiotombuf.

## 4. Compile Switch and Example
- `lib/Makefile:212  CFLAGS+= -DFSTACK_ZC_SEND`
- `example/main_zc.c`: call sequence `ff_zc_mbuf_get → ff_zc_mbuf_write (can be multiple times) → ff_zc_send`.

## 5. Mirrorable / Non-Mirrorable Points for ZC-READ
| Dimension | SEND (existing) | READ (target) | Mirrorable? |
|---|---|---|---|
| Direction | user constructs mbuf→kernel | kernel mbuf→handed to user | ✗ opposite direction; the mechanism cannot be simply symmetric |
| Sentinel hook | uio_offset=MAGIC triggers m_uiotombuf | the read-side kernel already has the mp0 out-parameter (see 02) | ⚠ no need to mimic magic; reusing mp0 is better |
| struct ff_zc_mbuf | filled by get/write | can be reused to carry "the chain handed out by the kernel" | ✓ reusable/extensible |
| Data copy | bcopy fill + kernel zero-copy attach | target: eliminate soreceive→uiomove | ✓ this is the value point of ZC-read |
| Release contract | kernel frees on its own after taking over | **the DPDK mbuf cannot be reclaimed while the APP holds it; needs release(m_freem)** | ✗ new; a read-only difficulty (see 03) |

**Key judgment**: ZC-send is "user gives the kernel an mbuf", ZC-read is "kernel gives the user an mbuf"; the two are opposite in direction, so **the FSTACK_ZC_MAGIC mechanism cannot be simply replicated symmetrically**; the read side should preferentially reuse the `soreceive` mp0 out-parameter that already exists in the kernel (see 02, 05 for details).
