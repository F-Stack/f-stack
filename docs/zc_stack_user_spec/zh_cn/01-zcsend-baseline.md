# 01 · ZC-SEND 对标基线全链路（FSTACK_ZC_SEND / M8）

> 探针：probe-zcsend（只读实测）。所有引用 file:line:symbol 经核对。代码与注释冲突以代码为准。

## 0. 一句话概览
APP `ff_zc_mbuf_get` 申请 BSD mbuf 链 → `ff_zc_mbuf_write` 用 `bcopy` 填入 mbuf trailing space → `ff_zc_send` 把 **mbuf 链首指针**当 `iov_base`，并在 `uio_offset` 打哨兵 `FSTACK_ZC_MAGIC` → `kern_writev → dofilewrite`（offset=-1 保留 magic）→ 内核 `m_uiotombuf` 检测 magic → **直接把 iov_base 当 mbuf 链挂载，跳过 m_getm2 分配与 uiomove 拷贝**。
**方向：用户态构造 mbuf，内核接管（用户 → 内核）。**

## 1. API 层
### 1.1 `struct ff_zc_mbuf`（ff_api.h:347-352）
| 字段 | 含义 |
|---|---|
| `bsd_mbuf` | 指向 mbuf 链**链首**（传给内核的句柄）|
| `bsd_mbuf_off` | 当前写入位置所在 mbuf（多次 write 续写定位）|
| `off` | 已写累计偏移，APP 不应改（ff_api.h:350 注释）|
| `len` | get 申请的链总容量 |

### 1.2 `ff_zc_mbuf_get`（ff_veth.c:306-323）
- `m_getm2(NULL, max(len,1), M_WAITOK, MT_DATA, 0)`（L313）一次性分配可容 len 字节的 mbuf 链；
- 第 5 参 flags=0 → **不带 M_PKTHDR**；
- `bsd_mbuf=bsd_mbuf_off=mb; off=0; len=len`（L318-320）；失败返回 -1。

### 1.3 `ff_zc_mbuf_write`（ff_veth.c:325-356）
- 从 `bsd_mbuf_off` 续写，沿 m_next 遍历，每 mbuf 写 `min(M_TRAILINGSPACE(mb), 剩余)`（L341）；
- **仍是 `bcopy`（L342）** —— ZC 省的是"用户→内核"那次拷贝，填 mbuf 本身仍拷贝一次；
- 只更新各 mbuf `m_len`，**未更新 m_pkthdr.len**（L349-350 被注释）；总长由 ff_zc_send 的 nbytes 经 m_uiotombuf 的 total 体现。

### 1.4 `ff_zc_mbuf_read`（ff_veth.c:358-363）= 空 stub
`// DOTO: Support read zero copy; return 0;`。签名 `const char *data` 与"读出"语义不符，属未设计占位。

## 2. 用户态 syscall 层
- `ff_zc_send`（ff_syscall_wrapper.c:1199-1225，`#ifdef FSTACK_ZC_SEND`）：`aiov.iov_base=mb`（L1210）、`auio.uio_offset=FSTACK_ZC_MAGIC`（L1216）→ `kern_writev`（L1217）。
- 防误触：普通 `ff_write`（L1151）/`ff_writev`（L1175）显式 `uio_offset=0` opt-out（栈上 auio 的 uio_offset 未初始化会误触发 magic 致 m_demote GPF，见 L1146-1150 注释）。

## 3. 内核 hook 层（freebsd/kern/uipc_mbuf.c）
- `m_uiotombuf` 的 `#ifdef FSTACK_ZC_SEND` 分支（L2028-2046）：当 `uio->uio_offset == FSTACK_ZC_MAGIC`（L2041）→ 把 iov_base 当 mbuf 链直接挂载、跳过常规拷贝循环，并把 `uio->uio_offset` 改写为 `total`（L2046）。
- 哨兵：`FSTACK_ZC_MAGIC ((off_t)0xF8AC2C00F8AC2C00LL)`（freebsd/sys/mbuf.h:1868）。
- kern_writev → dofilewrite 传 `offset=(off_t)-1`，不覆盖 auio.uio_offset，故 magic 得以保留至 m_uiotombuf。

## 4. 编译开关与示例
- `lib/Makefile:212  CFLAGS+= -DFSTACK_ZC_SEND`
- `example/main_zc.c`：调用序列 `ff_zc_mbuf_get → ff_zc_mbuf_write(可多次) → ff_zc_send`。

## 5. 对 ZC-READ 的可镜像 / 不可镜像点
| 维度 | SEND（已有）| READ（目标）| 可镜像？ |
|---|---|---|---|
| 方向 | 用户构造 mbuf→内核 | 内核 mbuf→交用户 | ✗ 方向相反，机制不能简单对称 |
| 哨兵 hook | uio_offset=MAGIC 触发 m_uiotombuf | read 侧内核已有 mp0 出参（见 02）| ⚠ 不必仿 magic，复用 mp0 更优 |
| struct ff_zc_mbuf | get/write 填充 | 可复用承载"内核交出的链" | ✓ 可复用/扩展 |
| 数据拷贝 | bcopy 填 + 内核零拷贝挂载 | 目标：消除 soreceive→uiomove | ✓ 是 ZC-read 价值点 |
| 释放契约 | 内核接管后自行 free | **APP 持有期间不能回收，需 release(m_freem)** | ✗ 新增，read 独有难点（见 03）|

**关键判断**：ZC-send 是"用户给内核 mbuf"，ZC-read 是"内核给用户 mbuf"，二者方向相反，**不能简单对称复刻 FSTACK_ZC_MAGIC 机制**；read 侧应优先复用内核已存在的 `soreceive` mp0 出参（详见 02、05）。
