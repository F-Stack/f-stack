# M1 — 研究简报（Research Brief）

> English version: ../M1-research-brief.md

> 系列文档：`/data/workspace/f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/`
> 文档版本：v0.1（2026-05-28）
> 作者：m1-leader（因 m1-analyzer 子代理工具配给不足，由 Leader 主对话内同步执行调研产出，已记录于 `M1-execution-log.md` §3 打回事件 #1）
> 范围：M1 里程碑（spec `05-implementation-plan.md` §2.1，11 个 T-* 任务）启动前一次性内外调研
> 时效：本简报数据基于 2026-05-28 当日实测；对应 13.0/15.0 baseline 文件 mtime 分别为 2021-06-02 与 2025-05-20

---

## 目录

- §1 mips 架构在 FreeBSD 15.0 中的移除证据
- §2 libkern 13.0→15.0 变更
- §3 opencrypto 13.0→15.0 变更
- §4 crypto/ 子目录变更（重点 blowfish / chacha20_poly1305 / curve25519）
- §5 vm/ 13.0→15.0 变更
- §6 arch headers 变更（amd64 / x86 / arm64）
- §7 netipsec / netgraph / netinet/libalias 变更
- §8 F-Stack 社区相关资料
- §9 spec 与代码事实交叉验证（必修订项）
- §10 11 个 T-* 任务的具体执行建议
- 附录 A：实测命令清单（≥10 条，便于复现）

---

## §1 mips 架构在 FreeBSD 15.0 中的移除证据

### 1.1 实测：15.0 sys 树中已无 mips 子目录

```text
$ ls -d /data/workspace/freebsd-src-releng-15.0/sys/mips
ls: cannot access '/data/workspace/freebsd-src-releng-15.0/sys/mips': No such file or directory
```

### 1.2 实测：15.0 `sys/conf/files` 已无 mips 引用

```text
$ grep -cE 'mips' /data/workspace/freebsd-src-releng-15.0/sys/conf/files
0
```

13.0 同处亦为 0（`grep -cE 'mips' /data/workspace/freebsd-src-releng-13.0/sys/conf/files` → 0），说明 mips 引用早已不在通用 `sys/conf/files` 中（mips 历史上单独使用 `sys/conf/files.mips`，13.0 阶段已逐步退出）。

### 1.3 实测：15.0 `UPDATING` 中 mips 移除条目（多条）

```text
$ grep -niE 'mips' /data/workspace/freebsd-src-releng-15.0/UPDATING | head -10
751:    Following the general removal of MIPS support, the ath(4) AHB bus-
930:    Remove mips as a recognized target. This starts the decommissioning of
931:    mips support in FreeBSD. mips related items will be removed wholesale in
971:    Mips has been removed from universe builds. It will be removed from the
1463:   mips, powerpc, and sparc64 are no longer built as part of
1465:   not defined, mips, powerpc, and sparc64 builds will look for
1643:   The mips GXEMUL support has been removed from FreeBSD. MALTA* + qemu is
1647:   removed from the mips port.
2272:   If you want to selectively load things (eg on cheaper ARM/MIPS
```

> 关键引文（UPDATING:930-931）："Remove mips as a recognized target. This starts the decommissioning of mips support in FreeBSD. mips related items will be removed wholesale in [a future release]."
>
> 关键引文（UPDATING:751）："Following the general removal of MIPS support, the ath(4) AHB bus-..."

### 1.4 外部权威引用：FreeBSD 15.0 release notes

来源：<https://www.freebsd.org/releases/15.0R/relnotes/>（最后修改：2026-03-05；维护者 Kyle Evans）

> 原文摘录（章节 "Architectures"）：
> "The venerable 32-bit hardware platforms i386, armv6, and 32-bit powerpc have been retired. 32-bit application support lives on via the 32-bit compatibility mode in their respective 64-bit platforms. The armv7 platform remains as the last supported 32-bit platform. We thank them for their service."

**关键解读**：15.0 release notes **未单独提及 mips 移除**，因为 mips 在更早的版本（13/14 时代）已逐步 decommissioning，到 15.0 是已成事实。release notes 仅列出本次新退役的 32 位平台（i386 / armv6 / 32-bit powerpc）。这一点在 spec 03/04 中需要修订（spec 03 §2.x 部分章节将 mips 视为"FreeBSD 15.0 的变更"，应改为"早于 15.0 已完成的变更，15.0 中已成事实"）。

### 1.5 结论

- ✅ mips 架构在 15.0 sys 树中已完全不存在（实测）
- ✅ 15.0 UPDATING 多条历史条目（早期 13/14 时代条目沿用至 15.0）记录 mips decommissioning
- ⚠️ 15.0 release notes 未直接提 mips（已是历史既定事实）→ spec 03 相关描述需小幅修订（§9-1）

---

## §2 libkern 13.0→15.0 变更

### 2.1 NEW / DEL / DIFFER 统计（实测）

| 类别 | 数量 |
|---|---:|
| `[DEL]` 13.0 only | 9 |
| `[NEW]` 15.0 only | 4 |
| `[DIFFER]` 同名异容 | 77 |

实测命令：`diff -rq /data/workspace/freebsd-src-releng-13.0/sys/libkern /data/workspace/freebsd-src-releng-15.0/sys/libkern`

### 2.2 NEW/DEL 文件清单

**DEL（13.0 → 15.0 移除）**：

| 文件 | 说明 |
|---|---|
| `arm/ffs.S` | arm 架构 ffs 汇编实现，被 C 版本（`ffs.c` 等）取代 |
| `bcmp.c` | 旧 BSD `bcmp`，已转为 `memcmp` 别名 |
| `ffs.c` `ffsl.c` `ffsll.c` `fls.c` `flsl.c` `flsll.c` | 6 个 bit-find 函数 C 版被 builtin `__builtin_ffs/__builtin_fls` 取代（编译器内建） |
| `mcount.c` | 用户态 profiling 入口，已移到 lib/libc |

**NEW（15.0 新增）**：

| 文件 | 说明 |
|---|---|
| `crc16.c` | CRC-16 实现，新引入（部分网络/存储驱动需要） |
| `divmoddi4.c` | 64-bit 有符号 div+mod 联合实现（compiler-rt 风格） |
| `strnstr.c` | 限长 strstr，从用户态 libc 移植到内核 |
| `udivmoddi4.c` | 64-bit 无符号 div+mod 联合实现 |

### 2.3 F-Stack 现有改造范围（极小）

```text
$ diff -rq /data/workspace/f-stack/freebsd/libkern /data/workspace/freebsd-src-releng-13.0/sys/libkern
Files f-stack/freebsd/libkern/gsb_crc32.c and freebsd-src-releng-13.0/sys/libkern/gsb_crc32.c differ
```

**仅 1 个文件有 F-Stack 改造**（`gsb_crc32.c`），其余 85 个文件与 13.0 上游字节级一致。这意味着 T-libkern-01（cp -a + 改造叠加）的工作量极小：86 文件中仅需对 `gsb_crc32.c` 做 5 步法改造保留，其余可直接以 15.0 上游覆盖。

---

## §3 opencrypto 13.0→15.0 变更

### 3.1 NEW / DEL / DIFFER 统计

| 类别 | 数量 |
|---|---:|
| `[DEL]` | 3 |
| `[NEW]` | 3 |
| `[DIFFER]` | 33 |

### 3.2 NEW/DEL 清单（实测）

```text
Only in freebsd-src-releng-15.0/sys/opencrypto: ktls.h
Only in freebsd-src-releng-15.0/sys/opencrypto: xform_aes_cbc.c
Only in freebsd-src-releng-15.0/sys/opencrypto: xform_chacha20_poly1305.c
Only in freebsd-src-releng-13.0/sys/opencrypto: xform.c
Only in freebsd-src-releng-13.0/sys/opencrypto: xform_poly1305.h
Only in freebsd-src-releng-13.0/sys/opencrypto: xform_rijndael.c
```

**关键变化**：
- `xform.c` 被拆分为多个 `xform_<algo>.c` 子文件（通用化重构）
- `xform_rijndael.c` → `xform_aes_cbc.c`（命名规范化）
- `xform_poly1305.h` 头被合并入 `xform_chacha20_poly1305.c`（合二为一）
- 新增 `ktls.h`（KTLS Kernel TLS 接口头）

### 3.3 F-Stack 现有改造

```text
$ diff -rq /data/workspace/f-stack/freebsd/opencrypto /data/workspace/freebsd-src-releng-13.0/sys/opencrypto
(0 differ; opencrypto-only: 0; 13only: 0)
```

**F-Stack 对 opencrypto 子目录无改造**（与 13.0 字节一致），T-opencrypto-01 可直接 cp -a。

---

## §4 crypto/ 子目录变更（重点 blowfish / chacha20_poly1305 / curve25519）

### 4.1 NEW / DEL / DIFFER

| 类别 | 数量 |
|---|---:|
| `[DEL]` | 1 |
| `[NEW]` | **48** |
| `[DIFFER]` | 189 |

15.0 在 `crypto/` 下新增大量 OpenSSL 加速汇编（aarch64 / amd64 / arm / i386 各架构），这是 release notes 中 "OpenSSL has been updated to 3.5.4" 的源码层落地。

### 4.2 重要事实更正：blowfish 在 13.0 sys/crypto 下也不存在

```text
$ ls -d /data/workspace/freebsd-src-releng-13.0/sys/crypto/blowfish 2>&1
ls: cannot access ...: No such file or directory
$ ls -d /data/workspace/freebsd-src-releng-15.0/sys/crypto/blowfish 2>&1
ls: cannot access ...: No such file or directory
$ find /data/workspace/freebsd-src-releng-13.0/sys -name 'blowfish*' -o -name 'bf_*'
(no output)
$ ls /data/workspace/f-stack/freebsd/crypto/blowfish 2>&1
ls: cannot access ...: No such file or directory
```

**结论**：`crypto/blowfish` 在 13.0 / 15.0 / f-stack 三处**均不存在**。spec 05 §2.1 T-crypto-01 描述 "blowfish 删除（已在上游删）" 与代码事实不符，需修订（详见 §9-2）。可能的来源混淆：FreeBSD 的 blowfish 实际在 `sys/opencrypto/blowfish.c`（13.0）/ `sys/opencrypto/xform_blf.c`，且 15.0 的 opencrypto/ §3.2 已知不含 blowfish 相关文件——但本里程碑 T-opencrypto-01 不涉及单独删除 blowfish 动作（cp -a 即可）。

### 4.3 chacha20_poly1305 / curve25519：15.0 新增

```text
$ ls /data/workspace/freebsd-src-releng-15.0/sys/crypto/ | grep -iE 'chacha20_poly1305|curve25519'
chacha20_poly1305.c
chacha20_poly1305.h
curve25519.c
curve25519.h
```

这与 spec 05 §2.1 T-crypto-01 描述"新增 chacha20_poly1305.c/.h 与 curve25519.c/.h 保留不引入"一致 ✅。

### 4.4 F-Stack 现有改造（仅 1 处大小写差异）

```text
$ diff -rq /data/workspace/f-stack/freebsd/crypto /data/workspace/freebsd-src-releng-13.0/sys/crypto
Only in f-stack/freebsd/crypto/skein/amd64: skein_block_asm.s
Only in freebsd-src-releng-13.0/sys/crypto/skein/amd64: skein_block_asm.S
```

**仅 1 处差异**：`crypto/skein/amd64/skein_block_asm` 的扩展名大小写——`f-stack` 用 `.s`（小写），13.0 上游用 `.S`（大写）。15.0 上游同样为 `.S`（待 verify）。这是历史 case-rename 导致，T-crypto-01 时需注意：cp -a 后会同时引入 `.S` 文件，**必须删除 `.s` 旧版**避免重复编译。

---

## §5 vm/ 13.0→15.0 变更

### 5.1 NEW / DEL / DIFFER

| 类别 | 数量 |
|---|---:|
| `[DEL]` | 2 |
| `[NEW]` | 1 |
| `[DIFFER]` | 51 |

### 5.2 NEW/DEL 清单

```text
Only in freebsd-src-releng-13.0/sys/vm: default_pager.c     ← 默认 pager 已并入其他模块
Only in freebsd-src-releng-13.0/sys/vm: vm_swapout_dummy.c  ← swap-out dummy 实现已删（统一逻辑）
Only in freebsd-src-releng-15.0/sys/vm: uma_align_mask.h    ← UMA 对齐 mask 拆出独立头
```

### 5.3 F-Stack 现有改造（2 个文件）

```text
$ diff -rq /data/workspace/f-stack/freebsd/vm /data/workspace/freebsd-src-releng-13.0/sys/vm
Files f-stack/freebsd/vm/uma_core.c and freebsd-src-releng-13.0/sys/vm/uma_core.c differ
Files f-stack/freebsd/vm/uma_int.h and freebsd-src-releng-13.0/sys/vm/uma_int.h differ
```

**F-Stack 仅改造 2 个 UMA 文件**（`uma_core.c` + `uma_int.h`）。spec 05 §2.1 T-vm-01 备注"评估 uma_core 改动是否触及 F-Stack" → 实测证实需单独处理这 2 个文件（5 步法 SOP），其余 51 个文件 cp -a 即可。

---

## §6 arch headers 变更（amd64 / x86 / arm64）

### 6.1 amd64/include 13→15

| 类别 | 数量 |
|---|---:|
| DEL | 5 |
| NEW | 7 |
| DIFFER | 87 |

NEW 清单：`asan.h` / `msan.h` / `_pmap.h` / `pte.h` / `sdt_machdep.h` / `tls.h` / `xen/arch-intr.h`

### 6.2 x86/include 13→15

| 类别 | 数量 |
|---|---:|
| DEL | 0 |
| NEW | 8 |
| DIFFER | 51 |

NEW 清单：`clock.h` / `kvm.h` / `ppireg.h` / `timerreg.h` / `tls.h` / `vmware_guestrpc.h` / `x86_ieeefp.h` / `xen/arch-intr.h`

### 6.3 arm64/include 13→15

| 类别 | 数量 |
|---|---:|
| DEL | 1 |
| NEW | 13 |
| DIFFER | 76 |

NEW 清单（前 10 条实测）：`acle-compat.h` / `asan.h` / `cmn600_reg.h` / `cpu_feat.h` / `cpuinfo.h` / `msan.h` / `sdt_machdep.h` / `sysreg.h` / `tls.h` / `vmm_dev.h` ...

**spec 05 §2.1 T-arm-02 提到的 cmn600 / ptrauth 实测证据**：

```text
$ find /data/workspace/freebsd-src-releng-15.0/sys/arm64 -iname '*cmn600*' -o -iname '*ptrauth*'
freebsd-src-releng-15.0/sys/arm64/include/cmn600_reg.h
freebsd-src-releng-15.0/sys/arm64/arm64/ptrauth.c
freebsd-src-releng-15.0/sys/arm64/arm64/cmn600.c
```

**关键观察**：
- 15.0 引入 ASan / MSan 内核态支持（amd64 / arm64 同步新增 `asan.h` / `msan.h`）
- 15.0 引入 SDT machine-dep 头（`sdt_machdep.h` 三大架构均有）
- 15.0 引入 `tls.h`（TLS 内核态接口，三大架构同步）
- arm64 新增 `cmn600_reg.h`（Arm CMN-600 互联）+ `arm64/ptrauth.c`（Pointer Authentication）—— F-Stack 不用，按 T-arch-02 计划应 stub 化

### 6.4 F-Stack 对这些 arch 子目录的改造

未做单独 diff（amd64/x86/arm64 子目录文件数 255+125+286=666，超出 brief 范围）。建议在 T-arch-01/02 执行时先做 `diff -rq` 对比 f-stack vs 13.0/15.0，再决定改造点。**初步预判**：F-Stack 对 amd64/x86/arm64 的改造极少（按 §2-§7 其他子目录的规律推断），主要是 `include/` 头文件 cp -a 跟随。

---

## §7 netipsec / netgraph / netinet/libalias 变更

### 7.1 netipsec 13→15

| 类别 | 数量 |
|---|---:|
| DEL | 0 |
| NEW | 2 |
| DIFFER | 30 |

NEW：`ipsec_offload.c` / `ipsec_offload.h`（对应 release notes 中 "New in-kernel inline IPSEC offload infrastructure"）。

F-Stack 改造：**0 文件**（与 13.0 字节级一致）→ T-misc-01 中 netipsec 部分可直接 cp -a。

### 7.2 netgraph 13→15

| 类别 | 数量 |
|---|---:|
| DEL | 7 |
| NEW | 4 |
| DIFFER | 152 |

DEL 清单：
- `atm/`（整子目录删除）
- `bluetooth/drivers/h4/`（蓝牙 H4 driver 删除）
- `bluetooth/include/ng_h4.h`（配套头）
- `ng_atmllc.c` / `ng_atmllc.h`（ATM LLC node 删除）
- `ng_sppp.c` / `ng_sppp.h`（synchronous PPP 删除，UPDATING:981 已记录）

NEW 清单：
- `bluetooth/drivers/ubt/ng_ubt_rtl.c`（Realtek 蓝牙固件 driver）
- `ng_vlan_rotate.c` / `ng_vlan_rotate.h`（VLAN 旋转 node）

实测验证 ng_atmllc / ng_sppp 已不在 15.0 sys/netgraph：

```text
$ ls /data/workspace/freebsd-src-releng-15.0/sys/netgraph/ng_atmllc.* \
     /data/workspace/freebsd-src-releng-15.0/sys/netgraph/ng_sppp.* 2>&1
ls: cannot access ...: No such file or directory
```

这与 99 §12.12 已建立的 `tools/compat/include/netgraph/LEGACY.md` pattern 完全一致——本里程碑 T-misc-01 中 netgraph 部分需扩展该 LEGACY pattern：除 `.h` 头文件外，**`.c` 源文件 ng_atmllc / ng_sppp 也需 LEGACY 处理**（保留 13.0 字节）。这是 spec 05 §2.1 中未充分展开的细节，详见 §9-3 修订建议。

F-Stack 现有改造：

```text
Files f-stack/freebsd/netgraph/ng_socket.c and freebsd-src-releng-13.0/sys/netgraph/ng_socket.c differ
Files f-stack/freebsd/netgraph/ng_socket.h and freebsd-src-releng-13.0/sys/netgraph/ng_socket.h differ
```

仅 `ng_socket.c/.h` 2 个文件有 F-Stack 改造，其余 173 文件可 cp -a。

### 7.3 netinet/libalias 13→15

| 类别 | 数量 |
|---|---:|
| DEL | 0 |
| NEW | 1 (`alias_db.h`) |
| DIFFER | 19 |

F-Stack 现有改造：仅 `alias_sctp.h` 1 个文件。

---

## §8 F-Stack 社区相关资料

### 8.1 外部检索结果

执行 `web_search` 关键词 "F-Stack github freebsd 14 freebsd 15 upgrade port issue" 与 RAG 查询（公私统一知识库 / 腾讯公司编程指南知识库），均**未发现 F-Stack 项目本身针对 FreeBSD 14/15 升级的公开讨论或 issue**。这意味着本次升级是**首次**对 F-Stack 进行 13→15 跨版本移植的工作，无社区先行经验可参考；spec 系列与本简报构成主要决策依据。

### 8.2 间接相关：FreeBSD 14→15 升级指南（社区博客）

| URL | 摘录 |
|---|---|
| <https://wal.sh/research/freebsd-15.0-RELEASE> | "Always patch before major upgrades. EN-25:18 fixes the library ordering bug that bricks systems mid-upgrade. After successful upgrade, verify new features are working..." |
| <https://maxiujun.com/blog/upgrade-guide-moving-from-freebsd-14-x-to-15-0-release> | 14.x→15.0 升级流程，强调 pkgbase 注意事项 |
| <https://computingforgeeks.com/upgrade-freebsd-14-to-15/> | freebsd-update 升级实测 |

这些资料对 **OS 层升级** 有价值，但 F-Stack 是 **静态库方式集成 FreeBSD 内核协议栈**，OS 升级注意事项不直接适用——F-Stack 需要的是**源码层** port，按 spec 05 §4 的 5 步法 SOP 逐文件做。

### 8.3 启示

- F-Stack 13→15 是社区"无人区"工作（无前人经验）→ 必须严格走 spec + 实测，禁止依赖外部 best practice 假设
- spec 系列已是当前最完备的指导文档（v0.3 评审通过）
- 风险：13.0 与 15.0 间隔 4 年（2021-06 → 2025-05），跳过 14.x 中间版本可能错过 14.x 中的过渡 API；但 F-Stack 直接对接 15.0 后向兼容由 FreeBSD 内核保证

---

## §9 spec 与代码事实交叉验证（必修订项）

### §9-1 ⚠️ 部分一致：mips 移除时机

**spec 03 §2.x 部分章节**（待精确定位）将 mips 视为"FreeBSD 15.0 的变更"。实测显示 mips 是**早于 15.0**（13/14 时代）已逐步 decommissioning，到 15.0 仅剩 UPDATING 历史条目。15.0 release notes 未单独提 mips（已成历史既定事实）。

**建议**：在 99 §12.13 追加修订记录，将 03 中 mips 表述改为"在 13.x→15.0 之间已完成移除，截至 15.0 sys 树中已完全不存在 mips 子目录"。

### §9-2 ❌ 不一致 → 必须以代码为准：crypto/blowfish

**spec 05 §2.1 T-crypto-01 描述**："crypto/ 顶层 cp -a 15.0；blowfish 删除（已在上游删）；新增 chacha20_poly1305.c/.h 与 curve25519.c/.h 保留不引入"

**代码实测**：`crypto/blowfish` 在 **13.0 / 15.0 / f-stack 三处均不存在**。可能 spec 起草时混淆了 sys/crypto 与 sys/opencrypto（FreeBSD 的 blowfish 历史上在 opencrypto 下，且 15.0 已不含相关文件）。

**建议**：99 §12.13 中将 T-crypto-01 描述修订为"crypto/ 顶层 cp -a 15.0；新增 chacha20_poly1305.c/.h 与 curve25519.c/.h 保留不引入；T-crypto-01 不涉及 blowfish 单独删除（13.0/15.0 sys/crypto 均无 blowfish）"。

### §9-3 ⚠️ 部分一致：T-misc-01 netgraph 应包含 .c 源文件 LEGACY 处理

**spec 05 §2.1 T-misc-01 描述**："netipsec/ netgraph/ netinet/libalias/ 等子目录 cp -a 跟随升级"。

**问题**：未显式说明 `ng_atmllc.c` / `ng_sppp.c` 这两个 .c 源文件在 15.0 已被删除时的处理方式。99 §12.12 仅建立了 `tools/compat/include/netgraph/` 子目录下 `.h` 头文件的 LEGACY pattern（针对 ng_atmllc.h / ng_sppp.h），但 **`f-stack/freebsd/netgraph/` 子树**对应的 `.c` 源文件（如 13.0 中存在的 `ng_atmllc.c` / `ng_sppp.c`）需要同等处理：保留 13.0 字节版本 + LEGACY.md 标记。

**建议**：99 §12.13 中明确 T-misc-01 netgraph 子项的处置规则——cp -a 时跳过 ng_atmllc.* / ng_sppp.* 与 atm/ / bluetooth/drivers/h4/ / bluetooth/include/ng_h4.h，保留 13.0 字节副本 + 在 `f-stack/freebsd/netgraph/LEGACY.md` 列出（文件级 LEGACY pattern，与 99 §12.12 同质）。

### §9-4 ✅ 一致：其他章节

- §1 mips 整体退役（spec 03 / 04 已正确识别）
- §2 libkern API 变更范围（spec 05 §2.1 T-libkern-01 ~70 估算与实测 86 偏小，但量级一致）
- §3 opencrypto xform_* 重构（spec 03 §3.10 / 05 §2.1 T-opencrypto-01 已识别）
- §5 vm/uma_core 改造（spec 05 §2.1 T-vm-01 已识别）
- §6 arch headers asan/msan/cmn600/ptrauth 等新增（spec 05 §2.1 T-arch-01/02 已识别）

---

## §10 11 个 T-* 任务的具体执行建议

### T-cleanup-01（P0，mips 整目录删除 + Makefile/mk 清理）

| 项 | 内容 |
|---|---|
| 关键差异点 | f-stack/freebsd/mips/ 实测 586 文件；lib/Makefile 行 195-201 含 mips 条件分支 |
| LEGACY 处理 | 否 → 整目录 cp -a 留档至 `/data/workspace/f-stack-mips-removed-2026-05/`，再 `rm -rf freebsd/mips/` |
| 顺序 | M1 第一步（其他任务依赖 mips 已删） |
| 风险 | 低；备份兜底；mk/*.mk 可能含 mips 条件分支需 grep 全量检查 |

### T-sys-01（P0，systm.h 5 步法 SOP）

| 项 | 内容 |
|---|---|
| 关键差异点 | 13.0 systm.h kpilite.h include 在行 179；15.0 移到行 100；F-Stack 在 13.0 基础上加 `#ifndef FSTACK` 屏蔽 kpilite.h；critical_enter/exit 在三处都通过 KBI 调用，但 15.0 行号不同 |
| LEGACY 处理 | 否 |
| 顺序 | T-cleanup-01 之后 |
| 风险 | 中；需准确识别 13.0→15.0 行号位移；c-precision-surgery skill 必须使用以保证最小 diff |

### T-sys-02（P0，refcount.h 5 步法 SOP）

| 项 | 内容 |
|---|---|
| 关键差异点 | 15.0 refcount_acquire_if_not_zero 在行 134；F-Stack 用 `#ifdef FSTACK` 包住 CAS 自检（行 120-146 区段） |
| LEGACY 处理 | 否 |
| 顺序 | T-sys-01 之后 |
| 风险 | 中；CAS 自检 stub 需移植到 15.0 新行号 |

### T-sys-03（P1，callout.h + _callout.h 简化）

| 项 | 内容 |
|---|---|
| 关键差异点 | 13.0/15.0 文件大小差异较小（callout.h 6782→6428；_callout.h 2742→2713）；F-Stack 在 13.0 基础上有 ~94 字节增量（callout.h）/ -62 字节（_callout.h） |
| LEGACY 处理 | 否 |
| 顺序 | P0 之后开始 |

### T-libkern-01（P1，cp -a + gsb_crc32 改造保留）

| 项 | 内容 |
|---|---|
| 关键差异点 | 仅 `gsb_crc32.c` 1 个 F-Stack 改造文件需保留；其余 85 个直接 cp -a from 15.0 sys/libkern |
| 顺序 | T-sys-* 之后 |
| 风险 | 低；改造文件极少 |

### T-opencrypto-01（P1，全量 cp -a）

| 项 | 内容 |
|---|---|
| 关键差异点 | F-Stack 对 opencrypto/ 无任何改造；可整目录 cp -a |
| 顺序 | T-libkern-01 之后 |
| 风险 | 低 |

### T-vm-01（P1，cp -a + uma 改造保留）

| 项 | 内容 |
|---|---|
| 关键差异点 | F-Stack 改造 2 个 UMA 文件（uma_core.c + uma_int.h）需移植到 15.0 baseline；spec 05 已识别 |
| 顺序 | T-opencrypto-01 之后 |
| 风险 | 中；UMA 是 F-Stack 性能关键路径 |

### T-crypto-01（P2，cp -a + skein/.s 大小写处理 + 新加密原语保留）

| 项 | 内容 |
|---|---|
| 关键差异点 | crypto/skein/amd64/ 中 13.0/15.0 用 `.S` 而 f-stack 用 `.s`（大小写）；cp -a 后必须删除 `.s` 旧版；spec 05 中 "blowfish 删除"描述与代码事实不符（已澄清，见 §9-2） |
| 顺序 | P1 之后开始 |
| 风险 | 中；`.s`/`.S` 大小写易踩坑导致重复编译 |

### T-arch-01（P2，amd64/x86 头文件跟随）

| 项 | 内容 |
|---|---|
| 关键差异点 | NEW 7+8=15 个新头文件（asan.h / msan.h / tls.h / 等） |
| 顺序 | T-crypto-01 之后 |
| 风险 | 中；需先做 f-stack vs 13.0 的 diff -rq 确定改造点（本 brief 未做），再决定改造叠加 |

### T-arch-02（P2，arm64 头文件 + cmn600/ptrauth stub）

| 项 | 内容 |
|---|---|
| 关键差异点 | NEW 13 个头（含 cmn600_reg.h / cpu_feat.h / sysreg.h / vmm_dev.h 等）；cmn600.c/ptrauth.c 在 sys/arm64/arm64/ 下 |
| LEGACY 处理 | cmn600 / ptrauth F-Stack 不用 → 头文件随上游 cp -a 但不主动引入 .c 编译（按 spec 05 stub 化处理） |
| 顺序 | T-arch-01 之后 |

### T-misc-01（P2，netipsec / netgraph / netinet/libalias）

| 项 | 内容 |
|---|---|
| 关键差异点 | netipsec：30 文件 cp -a（无改造）；netgraph：173 文件 cp -a + ng_socket.c/.h F-Stack 改造保留 + ng_atmllc.* / ng_sppp.* / atm/ / bluetooth h4 LEGACY 处理（详见 §9-3）；netinet/libalias：alias_sctp.h F-Stack 改造保留 + alias_db.h 新增 cp |
| LEGACY 处理 | 是（netgraph 多个文件，文件级 LEGACY pattern） |
| 顺序 | M1 末（依赖 netgraph LEGACY pattern 的 spec §9-3 修订就位） |
| 风险 | 中-高；LEGACY 处置范围需在 §9-3 修订到位后再执行 |

---

## §10.1 给 Leader 的 TOP 3 风险

1. **§9-2 spec 与代码事实硬冲突（blowfish）需在 T-crypto-01 执行前修订**：blowfish 在 13.0/15.0/f-stack 三处均不存在，spec 05 §2.1 T-crypto-01 描述需更正。如不更正，T-crypto-01 执行 Reviewer 审查时会反复触发"为什么没删 blowfish"的打回事件。
2. **§9-3 netgraph LEGACY 范围扩展（含 .c 源文件）**：99 §12.12 仅建立 `.h` 头 LEGACY pattern；本里程碑 T-misc-01 还需新增 `.c` 源文件 LEGACY pattern 以处理 `ng_atmllc.c` / `ng_sppp.c` / `atm/` / `bluetooth h4/`。需在 T-misc-01 执行前完成 spec 修订，否则 Coder 会卡在"netgraph 子目录 cp -a 时如何处置 13.0 独有文件"的不确定状态。
3. **arch 子目录（amd64/x86/arm64 共 666 文件）的 f-stack vs 13.0 diff -rq 尚未做**：本 brief §6 仅给出 13→15 上游 diff；T-arch-01/02 执行前必须由 Coder 先做 f-stack vs 13.0 实测，找出 F-Stack 在 arch headers 下的全部改造点（按 §2-§7 规律推断改造点应该极少，但需实测确认而非推断）。

---

## 附录 A：实测命令清单（≥10 条，便于复现）

```bash
# §1 mips 移除证据
ls -d /data/workspace/freebsd-src-releng-15.0/sys/mips
grep -nE 'mips' /data/workspace/freebsd-src-releng-15.0/sys/conf/files
grep -niE 'mips' /data/workspace/freebsd-src-releng-15.0/UPDATING | head -10
grep -nE 'mips' /data/workspace/freebsd-src-releng-15.0/ObsoleteFiles.inc

# §2-§7 子目录全量 NEW/DEL/DIFFER
diff -rq /data/workspace/freebsd-src-releng-13.0/sys/libkern    /data/workspace/freebsd-src-releng-15.0/sys/libkern
diff -rq /data/workspace/freebsd-src-releng-13.0/sys/opencrypto /data/workspace/freebsd-src-releng-15.0/sys/opencrypto
diff -rq /data/workspace/freebsd-src-releng-13.0/sys/crypto     /data/workspace/freebsd-src-releng-15.0/sys/crypto
diff -rq /data/workspace/freebsd-src-releng-13.0/sys/vm         /data/workspace/freebsd-src-releng-15.0/sys/vm
diff -rq /data/workspace/freebsd-src-releng-13.0/sys/netipsec   /data/workspace/freebsd-src-releng-15.0/sys/netipsec
diff -rq /data/workspace/freebsd-src-releng-13.0/sys/netgraph   /data/workspace/freebsd-src-releng-15.0/sys/netgraph
diff -rq /data/workspace/freebsd-src-releng-13.0/sys/netinet/libalias /data/workspace/freebsd-src-releng-15.0/sys/netinet/libalias
for arch in amd64 x86 arm64; do
  diff -rq /data/workspace/freebsd-src-releng-13.0/sys/$arch/include /data/workspace/freebsd-src-releng-15.0/sys/$arch/include
done

# F-Stack 改造范围（每个 M1 子目录）
for d in libkern opencrypto crypto vm netipsec netgraph netinet/libalias; do
  diff -rq /data/workspace/f-stack/freebsd/$d /data/workspace/freebsd-src-releng-13.0/sys/$d
done

# §1.4 sys 头文件 4 个改造重做关键点
grep -nE 'critical_enter|critical_exit|kpilite' /data/workspace/freebsd-src-releng-13.0/sys/sys/systm.h
grep -nE 'critical_enter|critical_exit|kpilite' /data/workspace/freebsd-src-releng-15.0/sys/sys/systm.h
grep -nE 'critical_enter|critical_exit|kpilite|FSTACK' /data/workspace/f-stack/freebsd/sys/systm.h
grep -nE 'refcount_acquire_if_not_zero|FSTACK' /data/workspace/f-stack/freebsd/sys/refcount.h

# 外部权威引用
# https://www.freebsd.org/releases/15.0R/relnotes/  (FreeBSD 15.0 release notes; web_fetch 已验证)
```

---

## 附录 B：本简报数据有效期与产出方式说明

- **数据基线**：2026-05-28 实测；13.0/15.0 baseline 文件 mtime 分别 2021-06-02 / 2025-05-20；f-stack 工作区 git HEAD `1aa558c2a`
- **产出方式说明**：原计划由 m1-analyzer 子代理（subagent_name=code-explorer）独立产出；实际执行时该子代理工具配给不足（仅 4 个只读工具，缺 write_to_file / bash / web_search / RAG），无法满足本简报对实测命令产出与外部引用的硬要求。Leader 收到子代理"无法执行"上报后，按 spec 05 §7.1 Gate 失败处理风格触发"打回 → 上一阶段重做"，由 Leader 主对话内同步执行（具备完整工具集），结果记入 `M1-execution-log.md` §3 打回事件 #1。
- **后续事件**：本简报产出后立即用于 §10 任务计划制定；§9 三项 spec 修订建议在 M1 末统一回写 99 §12.13。
