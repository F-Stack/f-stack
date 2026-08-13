# M18 遗留风险专项 —— spec 文档审核门禁报告（K / gate-doc2）

审核方：gate-doc2（只审不改，写审分离：doc-writer2 是写方）。
审核对象：`docs/native_mt_spec/zh_cn/18-遗留风险专项处理.md`（doc-writer2 更新后版本）。
交叉核对依据：`git --no-pager diff lib/ freebsd/ tests/`、`_m18_H_p136_coder.md`、`_m18_I_p136_review.md`、`_m18_J_p136_runtime.md`、`_m18_A~G`、`plan-18-legacy-risk.md`。

**总结论：PASS-with-fixes**（2 项事实一致性瑕疵需修正，均不影响 P1/P3/P6 修复结论本身）。

---

## 1. 事实一致性 —— 部分通过（发现 2 处瑕疵）

### 1.1 P1 / P3 / P6 修复描述与 git diff 一致性（坐实，PASS）

逐项比对 spec §3.5 / §3.6 / §3.4 与 `git diff` 实际代码：

- **P1 `dyn_hp` 显式数组**（spec §3.5 ↔ `git diff freebsd/netpfil/ipfw/ip_fw_dynamic.c`）：
  - `DPCPU_DEFINE_STATIC(void *, dyn_hp)` → `static void **dyn_hp`，`DYNSTATE_GET(cpu)`=`ck_pr_load_ptr(&dyn_hp[(cpu)])`、`DYNSTATE_PROTECT(v)`=`ck_pr_store_ptr(&dyn_hp[curcpu],(v))`：**逐字一致**。
  - `dyn_init`/`dyn_uninit` 中 `dyn_hp` 与 `dyn_hp_cache` 对称 malloc/free：**一致**。
- **P3 `__atomic_exchange_n`**（spec §3.6 ↔ `git diff freebsd/netinet/tcp_hpts.c`）：
  - `__atomic_exchange_n(&hpts->p_hpts_active, 1, __ATOMIC_ACQUIRE)` 抢占 + 结尾 `__atomic_store_n(..., 0, __ATOMIC_RELEASE)`，移除 `out_with_mtx`/`HPTS_UNLOCK`/二次检查/`p_hpts_active = 1`：**逐字一致**。
- **P6 `ff_pcpu_get()` 惰性 fail-fast**（spec §3.4 ↔ `git diff lib/include/amd64/include/pcpu.h`）：
  - `panic` 前置声明 + `ff_pcpu_get()`（`__builtin_expect(pcpup==NULL,0)`→panic），`get_pcpu`/`PCPU_GET`/`PCPU_ADD`/`PCPU_INC`/`PCPU_PTR`/`PCPU_SET` 全部改经 `ff_pcpu_get()`：**逐字一致**。
  - `lib/ff_api.h` 契约注释措辞（lazy fail-fast / pcpup is NULL in the new thread）：**与 git diff 一致**。

数据核对（spec §4 ↔ 过程文档）：
- clean build `error 0 / warning 51`、单测 `5/5 PASSED`：与 `_m18_H` §3、`_m18_I` §6 一致。
- `TCP Hpts created 1/2`、T1/T2 PASS、T3 环境 L2 不通：与 `_m18_J` §T1/T2/T3 一致。
- 无臆造、无「未坐实→已验证」翻转：spec 对 P1/P3/P6 的运行时边界（ipfw 未覆盖、P3 未压测、P6 只验零回归）均如实标注，见 §1.4。

### 1.2 瑕疵 1：代码事实基线 hash 过时（必改）

spec 第 3 行：「代码事实基线 `git HEAD = 9ef6dc92e`」。

实际：
- 当前 `git log -1` = **`e0fb11c9c`**（"docs: add native-mt leftover risk (M18) analysis and spec"）。
- 本轮 P1/P3/P6 补修过程文档 `_m18_H`/`_m18_I`/`_m18_J` 均标注 HEAD **`e0fb11c9c`**。
- `9ef6dc92e` 是 M18 最初 plan/编码/审核/运行时阶段（P2/P4/P5/P6 第一轮 + P1/P3 独立立项）的基线；P1/P3/P6 补修发生在 `faeeae2d9`（"Fix native-mt leftover risks in lib"，仅含 P2/P4/P5/P6 第一轮 4 文件）之后、`e0fb11c9c` 之上。

定性：spec 把「git HEAD」误标为过时的 `9ef6dc92e`，与当前实际 HEAD、与 `_m18_H/I/J` 的基线标注均不符。属事实不一致，需改为 `e0fb11c9c`（或明确区分「存在性分析基线 9ef6dc92e」与「P1/P3/P6 补修基线 e0fb11c9c」两个时间点）。

### 1.3 瑕疵 2：§3.4 文件清单遗漏 `tests/unit/Makefile`（必改）

spec §3.4 文件清单：「`lib/include/amd64/include/pcpu.h`（核心）、`lib/ff_api.h`（契约注释）、`tests/unit/test_ff_thread.c`（新增 fail-fast 用例）；`lib/ff_thread.c` 与 `lib/ff_api.symlist` 保持 HEAD 原样（无 diff）。」

实际 `git diff --stat` 本轮 6 文件含 **`tests/unit/Makefile`**（1 行改动：`test_ff_thread` 链接规则新增 `-Wl,--wrap=panic`）。spec §3.4 未列出该文件。

连带发现：`_m18_H` §1.3 声称「Makefile 复用，无改动」、`_m18_I` §3.5 声称「Makefile 已含 `-Wl,--wrap=panic`」，均与 git diff 显示「该行为本轮新增」不符。spec 作为汇总文档应如实列出 Makefile 这一改动（正是它提供了 `__wrap_panic` 重定向机制，是 P6 单测能跑通的关键一环）。

定性：文件清单不完整，属事实遗漏，需在 §3.4 补充 `tests/unit/Makefile`（`-Wl,--wrap=panic`）。

---

## 2. 裁决一致性 —— PASS

- 汇总表（spec §1）6 项全部「坐实 + 修 + 已修复」，无残留「P1/P3 独立立项」「P6 纯文档化」的旧裁决。
- §5 明确「P1：已修复，原『独立立项』撤销」「P3：已修复，原『独立立项』撤销」「P6：已修复（惰性 fail-fast）」，表述准确，符合「§5 的历史说明可保留『原独立立项撤销』」的允许范围。
- 【注1】明确 P1/P3/P6 为本轮补齐修复，与 P2/P4/P5 前一轮修复区分清晰。
- 【注3】完整解释了 P6 从「入口 fail-fast（方案 6-A）」→「惰性 fail-fast」的演变（TLS 语义矛盾 + 无法单测），与 `_m18_H` §2.1、`_m18_D` §6 一致，无翻转。

## 3. 真实 IP —— PASS

全文 grep `9\.134\.\d+\.\d+` 与 `2402:4e00:[0-9a-fA-F:]+` 命中 0 处。无任何完整真实 IP；`<DPDK_NIC_IP>`/`127.0.0.1` 占位/回环形式合规。

## 4. 诚实边界 —— PASS

- §5 逐项保留 P1（ipfw dynamic 运行时未覆盖）/ P3（高并发未压测）/ P6（热路径性能/fail-fast 异常路径未运行时验证）的未坐实边界，未翻转。
- 末尾【未坐实边界说明】完整保留全部 6 项的未坐实项（P1 其它 DPCPU 消费者、P3 `mp_ncpus` 是否恒等于 worker 数、P2 丢失更新量化、P4 运行时外部改写面、P5 极端并发、P6 异常路径 + 热路径），与 `_m18_A`/`_m18_C` 的「未坐实项」章节对应，无臆造。

## 5. 写作风格 —— PASS

- 编号标题（1./2./2.1…/3.1…/4.1…/5.），无 Markdown `#` 多级标题滥用。
- 无「总结」「结语」硬小标题（§5 用「遗留项与独立立项」、末尾用「延伸阅读」，均非客套标题）。
- 无 emoji、无「本文将介绍」套话、无「希望对你有帮助」结尾客套。

---

## 6. 必改项汇总

| # | 位置 | 问题 | 修正建议 |
| --- | --- | --- | --- |
| 1 | spec 第 3 行 | 基线 hash `9ef6dc92e` 过时，当前 HEAD 为 `e0fb11c9c` | 改为 `e0fb11c9c`，或区分「存在性分析基线 9ef6dc92e / P1/P3/P6 补修基线 e0fb11c9c」 |
| 2 | spec §3.4 文件清单 | 遗漏 `tests/unit/Makefile`（本轮 6 文件之一，+`-Wl,--wrap=panic`） | 在 §3.4 补充 `tests/unit/Makefile` 及改动说明 |

两项均为事实一致性瑕疵（文件清单遗漏 + 基线 hash 过时），不涉及 P1/P3/P6 修复结论本身的正确性（代码已由 `_m18_I` 独立审核 PASS、`_m18_J` 运行时 T1/T2 PASS 坐实）。

## 7. 最终结论

**PASS-with-fixes**

- 核心事实（P1/P3/P6 修复描述、file:line、clean build/单测/运行时数据）与 git diff、过程文档一致，无臆造、无翻转。
- 裁决一致性、真实 IP、诚实边界、写作风格四项均 PASS。
- 必改 2 项（基线 hash + Makefile 清单），属文档层面事实修正，由 doc-writer2 修正后即可通过，无需重跑代码门禁。
