# 31. Current-state Mapping and Removal List — Full Map of the `FSTACK_ZC_SEND` Old Path

> Source: the measured report of the probe-zcsend-current sub-agent (grep + read, full file:line:symbol anchors)
> Scope: all kernel and userspace touchpoints that this spec mandates **whole removal** of (decision A — tear down immediately)
> Purpose: 33-kernel-patch-spec / 34-userspace-api-spec generate c-precision-surgery-style patches from this

---

## §1 Modification Map (17 sites in full, by file + line + symbol)

| # | File | Line | Symbol / context | Category | Disposition |
|---|---|---|---|---|---|
| 1 | `freebsd/sys/mbuf.h` | 1856–1869 | The whole `#ifdef FSTACK_ZC_SEND` block (including `#define FSTACK_ZC_MAGIC ((off_t)0xF8AC2C00F8AC2C00LL)`) | Sentinel macro | **DELETE** |
| 2 | `freebsd/kern/uipc_mbuf.c` | 1955–2077 | The `#ifndef FSTACK / #else` 13.0-era simplified `m_uiotombuf` wrapper | Kernel fast-path | **DELETE** (together with #3) |
| 3 | `freebsd/kern/uipc_mbuf.c` | 2028–2049, 2070–2072 | The `#ifdef FSTACK_ZC_SEND` fast-path branch inside `m_uiotombuf` | Kernel fast-path predicate | **DELETE** |
| 4 | `freebsd/kern/sys_generic.c` | 57 | `#include <sys/mbuf.h>  /* M8: FSTACK_ZC_MAGIC for ZC fast-path */` | Header inclusion | **DELETE** (if nothing else depends on this include) |
| 5 | `freebsd/kern/sys_generic.c` | 560–573 | The `#ifdef FSTACK_ZC_SEND` sentinel-preservation if/else inside `dofilewrite` | uio_offset pass-through | **DELETE** |
| 6 | `lib/ff_syscall_wrapper.c` | 32 | `#include <sys/mbuf.h>  /* M8: FSTACK_ZC_MAGIC for ff_zc_send */` | Header inclusion | **KEEP** (still need types such as `struct mbuf`) |
| 7 | `lib/ff_syscall_wrapper.c` | 1146–1151 | `auio.uio_offset = 0;` opt-out inside `ff_write` + 5 lines of comment | opt-out | **DELETE** |
| 8 | `lib/ff_syscall_wrapper.c` | 1175 | `auio.uio_offset = 0;` inside `ff_writev` | opt-out | **DELETE** |
| 9 | `lib/ff_syscall_wrapper.c` | 1186–1226 | The whole `#ifdef FSTACK_ZC_SEND ... ff_zc_send ... #endif` (including the `auio.uio_offset = FSTACK_ZC_MAGIC` injection) | ZC common entry | **REWRITE** (see 34) |
| 10 | `lib/ff_api.h` | 437–446 | `ssize_t ff_zc_send(int fd, const void *mb, size_t nbytes);` public signature + doc block | ABI | **KEEP signature, update doc block** (see 34) |
| 11 | `lib/ff_api.symlist` | 63 | `ff_zc_send` export symbol | so export | **KEEP** |
| 12 | `lib/Makefile` | 211–213 | `ifdef FF_ZC_SEND / CFLAGS+= -DFSTACK_ZC_SEND / endif` | Compile switch | **KEEP** (meaning switches: from "hack enabled" → "native path enabled") |
| 13 | `lib/Makefile` | 47 | `#FF_ZC_SEND=1` (commented by default) | Top-level enable comment | **KEEP** |
| 14 | `example/main_zc.c` | 132 | `extern ssize_t ff_zc_send(int fd, const void *mb, size_t nbytes); /* M8 */` | Caller prototype | **KEEP** |
| 15 | `example/main_zc.c` | 208–245 | The `#ifdef FSTACK_ZC_SEND` branch call sequence `ff_zc_mbuf_get/write/ff_zc_send` | Call sequence | **KEEP (zero modification)** — this is the contract verification point of ABI invariance |
| 16 | `example/Makefile` | 22, 26, 32, 34 | `FF_ZC_SEND=1` detection + `-DFSTACK_ZC_SEND` compile target `${TARGET}_zc` | Example compilation | **KEEP** |
| 17 | `lib/ff_veth.c` | 306–356 | `ff_zc_mbuf_get` (`m_getm2(..., 0)` **without `M_PKTHDR`**) + `ff_zc_mbuf_write` (commented-out `m->m_pkthdr.len += length;` at L349-350) | mbuf allocation/write | **REWRITE** (M_PKTHDR fix, see 34) |

---

## §2 Call Graph: the `FSTACK_ZC_MAGIC` Sentinel Flow Path (old solution)

```
APP (example/main_zc.c:209-244)
  ├── ff_zc_mbuf_get(&zc_buf, buf_len)          // ff_veth.c:306  m_getm2(..., MT_DATA, 0)  ← no M_PKTHDR
  ├── ff_zc_mbuf_write(&zc_buf, ...)            // ff_veth.c:326  bcopy to trailing space; pkthdr.len accumulation commented out
  └── ff_zc_send(fd, zc_buf.bsd_mbuf, buf_len)  // ff_syscall_wrapper.c:1199
        │
        │  [ MAGIC injection point ]
        │  auio.uio_offset = FSTACK_ZC_MAGIC;   // L1216
        │  aiov.iov_base   = (void*)mb;         // L1210  ← mbuf chain disguised as char*
        ▼
      kern_writev(curthread, fd, &auio)         // L1217
        │
        ▼
   freebsd/kern/sys_generic.c::sys_writev → kern_writev → dofilewrite
        │
        │  [ MAGIC guard point ]                // L560-573
        │  if (auio->uio_offset != FSTACK_ZC_MAGIC)
        │      auio->uio_offset = offset;       ← overwrite to -1 only when not MAGIC
        ▼
      fo_write(fp, auio, ...)                  // L579
        │  → soo_write → sosend_generic
        │     (uio still carries uio_offset == FSTACK_ZC_MAGIC)
        ▼
   freebsd/kern/uipc_mbuf.c::m_uiotombuf       // L2000-2076
        │
        │  [ MAGIC consumption point ]         // L2040-2046
        │  if (uio_segflg==UIO_SYSSPACE && uio_rw==UIO_WRITE
        │      && uio->uio_offset == FSTACK_ZC_MAGIC) {
        │      m = (struct mbuf *)uio->uio_iov->iov_base;   ← iov_base reinterpreted as mbuf
        │      uio->uio_offset = total;        ← MAGIC destroyed here
        │      progress = total;
        │  } else {
        │      ... slow path m_getm2 + uiomove
```

**External impact** (i.e. must remain unchanged after the G2 removal):
- The caller sequence (example/main_zc.c L208-245 unchanged);
- ff_zc_send / ff_zc_mbuf_get / ff_zc_mbuf_write signatures unchanged;
- The `FF_ZC_SEND=1` compile switch name unchanged;

The new solution (see 32 / 33 / 34) replaces the entire MAGIC injection/guard/consumption chain with:
- `ff_zc_send` → `kern_zc_sendit(td, s, top, flags)` → `sosend(so, NULL, NULL, top, NULL, flags, td)`
- No longer modifying any line of `kern_writev` / `m_uiotombuf` / `mbuf.h`.

---

## §3 Precise References of the Sections to Delete (c-precision-surgery anchor format)

> Anchor format: each section contains "5 lines before + section to delete + 5 lines after", to facilitate a single precise replacement by the implementation-phase agent.
> Implementation-phase patch tool: `replace_in_file` (old string/new string), generated by the spec → implementation plan patch script.

### §3.1 anchor: `freebsd/sys/mbuf.h:1856-1869` (delete the FSTACK_ZC_MAGIC macro)

```c
// anchor (preceding 5 lines) — 1851-1855:
#endif

#define MBUF_PROBE3(probe, arg0, arg1, arg2)                 \
        SDT_PROBE3(sdt, , , probe, arg0, arg1, arg2)
#define MBUF_PROBE4(probe, arg0, arg1, arg2, arg3)           \
        SDT_PROBE3(sdt, , , probe, arg0, arg1, arg2, arg3)

// section to delete — 1856-1869:
#ifdef FSTACK_ZC_SEND
/*
 * M8 zero-copy send fast-path sentinel.
 * ff_zc_send stamps uio->uio_offset with this magic value to tell
 * m_uiotombuf (uipc_mbuf.c) that uio->uio_iov->iov_base is actually
 * a pre-built mbuf chain (NOT a char buffer), so it can be adopted
 * verbatim and the regular uiomove copy loop should be skipped.
 *
 * Plain ff_write / ff_writev paths must explicitly clear uio_offset
 * (see lib/ff_syscall_wrapper.c) so they never collide.
 */
#define FSTACK_ZC_MAGIC ((off_t)0xF8AC2C00F8AC2C00LL)
#endif

// anchor (following 5 lines) — 1870-1874:
#endif /* _KERNEL */

#endif /* !_SYS_MBUF_H_ */
```

Under the new solution the whole block (including `#ifdef FSTACK_ZC_SEND ... #endif` + comment + #define) is **deleted as a whole**.

### §3.2 anchor: `freebsd/kern/uipc_mbuf.c:2028-2072` (delete the ZC branch of m_uiotombuf)

> The sub-agent report shows `freebsd/kern/uipc_mbuf.c:1955-2077` is the whole 13.0-era simplified m_uiotombuf (not vanilla 15.0), of which L2028-2049 + L2070-2072 are the `#ifdef FSTACK_ZC_SEND` branch. This cycle recommends **reverting to the vanilla FreeBSD 15.0 m_uiotombuf** (i.e. delete the whole 1955-2077 section and restore the upstream version). See 33-kernel-patch-spec.md §3 for the detailed restoration plan.

### §3.3 anchor: `freebsd/kern/sys_generic.c:560-573` (delete the dofilewrite uio_offset guard)

```c
// anchor (preceding 5 lines) — 555-559 (measured, corrected):
#endif

	AUDIT_ARG_FD(fd);
	auio->uio_rw = UIO_WRITE;
	auio->uio_td = td;

// section to delete — 560-573 (measured):
#ifdef FSTACK_ZC_SEND
	/*
	 * M8: preserve FSTACK_ZC_MAGIC sentinel set by ff_zc_send so it
	 * survives down to m_uiotombuf where the ZC fast path tests for
	 * it. Plain ff_write callers pass uio_offset = 0, which is
	 * indistinguishable from default offset = -1 here, so we still
	 * overwrite for them (the fast-path predicate also checks
	 * UIO_SYSSPACE/UIO_WRITE which everyone has).
	 */
	if (auio->uio_offset != FSTACK_ZC_MAGIC)
		auio->uio_offset = offset;
#else
	auio->uio_offset = offset;
#endif

// anchor (following 5 lines) — 574-578 (measured, corrected):
#ifdef KTRACE
	if (KTRPOINT(td, KTR_GENIO))
		ktruio = cloneuio(auio);
#endif
	cnt = auio->uio_resid;
```

The new solution deletes the whole `#ifdef FSTACK_ZC_SEND ... #else ... #endif` section above, keeping only the single line `auio->uio_offset = offset;`. Also, if L57 `#include <sys/mbuf.h>` was introduced only for the MAGIC, delete it as well (the implementation phase needs to grep-verify whether sys_generic.c uses mbuf types elsewhere).

### §3.4 anchor: `lib/ff_syscall_wrapper.c:1146-1151` (delete the ff_write opt-out)

```c
// anchor (preceding 5 lines) — 1141-1145:
    auio.uio_iovcnt = 1;
    auio.uio_resid = nbytes;
    auio.uio_segflg = UIO_USERSPACE;

    /* M8: explicitly clear uio_offset so the FSTACK_ZC_SEND fast path

// section to delete — 1146-1151:
     * (uipc_mbuf.c:2028) sees a normal write and not a chance match
     * with FSTACK_ZC_MAGIC (0xF8AC2C00F8AC2C00LL). All non-ZC ff_write
     * callers carry plain char buffers; this is a safety opt-out.
     */
    auio.uio_offset = 0;
    /* Note: kern_writev consults uio_offset only via dofilewrite;

// anchor (following 5 lines) — 1152-1156:
     * the lseek-style use here is harmless. */
    if ((rc = kern_writev(curthread, fd, &auio)))
        ...
```

### §3.5 anchor: `lib/ff_syscall_wrapper.c:1175` (delete the ff_writev opt-out)

```c
// anchor (preceding 5 lines) — 1170-1174:
    auio.uio_iovcnt = iovcnt;
    auio.uio_resid = total;
    auio.uio_segflg = UIO_USERSPACE;

    auio.uio_offset = 0; /* M8: see ff_write comment */

// section to delete — 1175:
    auio.uio_offset = 0; /* M8: see ff_write comment */

// anchor (following 5 lines) — 1176-1180:
    if ((rc = kern_writev(curthread, fd, &auio)))
        ...
```

### §3.6 anchor: `lib/ff_syscall_wrapper.c:1186-1226` (rewrite ff_zc_send, see 34)

The whole section (including `#ifdef FSTACK_ZC_SEND ... ff_zc_send ... #endif`) is replaced with the new version (based on `kern_zc_sendit`), see 34-userspace-api-spec.md §3.

### §3.7 anchor: `lib/ff_veth.c:306-356` (fix the M_PKTHDR of ff_zc_mbuf_get/write)

See 34-userspace-api-spec.md §4. **Key changes**:
- L313 `m_getm2(NULL, max(len, 1), M_WAITOK, MT_DATA, 0)` → `m_getm2(NULL, max(len, 1), M_WAITOK, MT_DATA, M_PKTHDR)`
- L349-350 the commented-out `pkthdr.len += length` becomes effective code (accumulate only at the chain head, O(1) maintenance of the total)

---

## §4 ABI Invariance Evidence

### §4.1 Public Signatures (lib/ff_api.h:437-446)

```c
ssize_t ff_zc_send(int fd, const void *mb, size_t nbytes);
int ff_zc_mbuf_get(struct ff_zc_mbuf *m, int len);
int ff_zc_mbuf_write(struct ff_zc_mbuf *m, const char *data, int len);
```

→ Under the new solution all three signatures are **fully preserved**; only the implementation changes.

### §4.2 Caller Sequence (example/main_zc.c:208-245)

Under the new solution this sequence passes with **zero modification**; this is the contract verification point of G4 ABI invariance (also one of the AC2 acceptance conditions).

### §4.3 Export Symbol (lib/ff_api.symlist:63)

`ff_zc_send` single symbol; the new solution does not add, remove, or change it.

### §4.4 Compile Switch (lib/Makefile:211-213)

```makefile
ifdef FF_ZC_SEND
CFLAGS+= -DFSTACK_ZC_SEND
endif
```

The new solution keeps the macro name `FSTACK_ZC_SEND`, but **the meaning switches**:
- Old: enable the hacked `m_uiotombuf` branch + uio_offset sentinel
- New: enable the `kern_zc_sendit` entry + ff_zc_mbuf_get/write going through the M_PKTHDR path

The only requirement for migrators: **recompile after `make clean`** (consistent with the M2-phase lesson, see 39 migration guide).

---

## §5 Gate-verifiable Clauses (for gatekeeper spot-checks)

| Clause | Verification method | Pass criterion |
|---|---|---|
| C1 | `grep -rn "FSTACK_ZC_MAGIC" freebsd/ lib/` | After implementation only historical references in spec/docs should remain, 0 hits in source |
| C2 | `grep -rn "FSTACK_ZC_SEND" freebsd/kern/uipc_mbuf.c freebsd/kern/sys_generic.c freebsd/sys/mbuf.h` | 0 hits |
| C3 | `grep -n "auio.uio_offset = 0" lib/ff_syscall_wrapper.c` | 0 hits |
| C4 | `nm libfstack.a \| grep ff_zc_send` | Only 1 symbol definition (consistent with the old solution) |
| C5 | `diff example/main_zc.c (HEAD) example/main_zc.c (post-impl)` | 0 line changes |
| C6 | `diff freebsd/kern/uipc_mbuf.c (vanilla 15.0) freebsd/kern/uipc_mbuf.c (post-impl)` | 0 line changes (reverted to vanilla) |

---

Next: **32-native-arch-design.md** (new symmetric architecture diagram).
