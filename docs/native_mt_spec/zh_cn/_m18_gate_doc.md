# M18 遗留风险专项 —— spec 文档审核门禁报告（gate-doc）

审核方：gate-doc（只审不改；写审分离：doc-writer 是写方，本报告是独立审核方）。
仓库 `/data/workspace/f-stack`，HEAD `9ef6dc92e`。
审核对象：`docs/native_mt_spec/zh_cn/18-遗留风险专项处理.md`。
交叉核对依据：过程文档 `_m18_A/B/C/D/E/F/G` + `plan-18-legacy-risk.md` + 实际代码 `git --no-pager diff lib/`（独立实测）。

结论：**PASS-with-fixes**（无硬伤：无事实错误、无真实 IP、无「未坐实→已验证」翻转、裁决表述准确；存在 2 处轻微表述/完整性瑕疵需修正，见 §6）。

---

## 1. 事实一致性（PASS）

逐项实测核对：

### 1.1 实际代码 diff（独立 `git diff lib/` 复核）

最终交付态为 **4 文件改动**，与 spec §3 的最终形态完全一致：

| 文件 | 实测 diff | spec 声称 | 结论 |
| --- | --- | --- | --- |
| `lib/include/amd64/include/counter.h` | `counter_u64_fetch_inline`/`zero_inline`/`add` 三函数改 `__atomic_load_n`/`__atomic_store_n`/`__atomic_fetch_add`（`__ATOMIC_RELAXED`） | §3.1 三函数原子化 | 一致 |
| `lib/ff_freebsd_init.c` | 注入循环内 `strcmp(cur->name, "net.isr.dispatch")==0` → `printf` 告警 + `continue` | §3.2 启动期防护 | 一致 |
| `lib/ff_subr_prf.c` | `__thread char bufr[...]` + `static __thread int putbuf_done` 两行 | §3.3 两行 `__thread` | 一致 |
| `lib/ff_api.h` | `ff_pthread_create` 声明上方契约注释（`undefined behaviour and will crash`） | §3.4 纯文档化 | 一致 |

**关键坐实点（对应审核项 1 的专项核对）**：
- `git diff lib/ff_thread.c` **为空** —— P6 fail-fast 已回退到 HEAD 原样，与 spec §3.4 /【注1】/【注3】「纯文档化」一致。✓
- `grep pcpup lib/ff_api.symlist` **无命中** —— `pcpup` 导出已删除，与 spec【注3】「删除新增 pcpup 导出」一致。✓
- P2 确为 `counter.h` 三函数原子化（`__ATOMIC_RELAXED`），`counter_u64_add_protected`（`#define`）与 `counter_enter/exit`（空操作）未改。✓
- P4 确为 `ff_freebsd_init.c` 特判（`strcmp` + `continue`），非「注入后校验改回」。✓
- P5 确为两行 `__thread`。✓

### 1.2 关键 file:line 实测

| spec 引用 | 实测 | 结论 |
| --- | --- | --- |
| P5 `bufr` @ `:86`、`putbuf_done` @ `:89`、`PRINTF_BUFR_SIZE 256` @ `:82` | 86 / 89 / 82 | 一致 |
| P5 `vprintf` @ `:550` | 550 | 一致 |
| P6 `pcpup` @ `ff_freebsd_init.c:89` | 89 | 一致 |
| P6 `ff_pcpu_thread_init` 定义 `:104`、调用 `:191`/`:317` | 104 / 191 / 317 | 一致 |
| P6 `pcpu.h:34`=curcpu、`amd64/include/pcpu.h:49`=PCPU_GET | 34 / 49 | 一致 |
| P6 `ff_thread.c:20-30`/`:32-46` | 与源码一致（`ff_set_thread(parent)` 后无 pcpup 检查） | 一致 |

注：P5 `putbuf()` spec 写 `:136-177`，实测函数体起点在 `:137`（1 行偏差）；此偏差系从过程文档 B 忠实转录，非 spec 独有引入，函数范围判断不受影响，不计为错误。

### 1.3 数据点核对（均与过程文档一致）

- `error 0 / warning 51`（lib）、`error 0 / warning 0`（example）：E §3 / F §4 一致。✓
- 单测 `4/4 PASSED`（4 个用例名逐一对应）：E §5.1 一致。✓
- T1/T2/T3 全 PASS、`TCP Hpts created 2 swi interrupt threads`（hpts=2=worker 数）：G §T2 一致。✓
- `counter_u64_add(` 全仓 `≥ 85` 处：B §4 一致。✓

**无臆造、无夸大、无「未坐实→已验证」翻转**：spec §4.3 T1 明确「连通性验证因环境 L2 不通未执行」、T2 明确「未做高强度并发打印压测」、末尾【未坐实边界说明】逐项保留 P1-P6 未坐实项，与过程文档的诚实边界一致。

## 2. 裁决表述准确（PASS）

- P1 / P3 「不修（独立立项）」，立项名与修复方向与 D §1.4 / §3.3、A 文档一致。✓
- P6 「纯文档化」裁决与 leader 决策（E §5 bounce=1「回退 fail-fast、仅保留 ff_api.h 契约注释」）一致。✓
- 汇总表「裁决」「结果」两列准确：P2 原子化 / P4 启动防护 / P5 两行 `__thread` / P6 纯文档化，与最终 4 文件交付态一一对应。✓
- P6 时序诚实处理：§4.1【注4】明确「review 通过的是 fail-fast 版本，其后 leader 裁决回退为纯文档化，最终交付态以 §3 为准」——无时序混淆。✓

## 3. 真实 IP（PASS）

全文检索 `9.134.` / `2402:4e00:` / `fe80::` / `127.0.0.1`：**0 命中**。spec 描述运行时测试时未引用任何具体地址（连 `<DPDK_NIC_IP>` 占位符都未使用），无真实 IP 泄露。

## 4. 诚实边界（PASS，含 1 处完整性瑕疵，见 §6.2）

spec §5 与末尾【未坐实边界说明】保留了主要未坐实项（P1 的 ipfw 是否启用/其它 DPCPU 消费者、P3 的并发重入/mp_ncpus、P2 的丢失更新量化、P4 的运行时外部改写面、P5 的极端并发、P6 的 fail-fast 回退），且正文各处措辞谨慎（「可能」「非确定故障」「无法断言」「未做」）。未发现把未坐实写成已验证。

## 5. 写作风格（PASS，含 1 处提示，见 §6.3）

- 编号标题（`1.` `2.` `2.1`-`2.6` `3.` `4.` `5.`）组织层次，正文无 `##`/`###` 子标题。✓
- 无「总结/结语」生硬小标题、无「希望本文有帮助」客套、无 emoji。✓

## 6. 需修正项（PASS-with-fixes 依据）

### 6.1 【建议】§4.1 / §4.2 的「本轮 6 文件」表述与最终 4 文件交付态不一致

spec §4.1「reviewer 独立复核 6 文件 diff」、§4.2「无一条来自本轮 6 文件」沿用 E §3 / F 文档的「6 文件」表述。但最终交付态是 **4 文件**（`ff_thread.c`、`ff_api.symlist` 已回退，见【注3】）。warning 51 在两个时点均成立（E §3 与 E §5.1 回退后重编均 51），数据无误，但「6 文件」措辞易让读者误以为最终有 6 个改动文件。建议改为「本轮改动文件」（或加注「review 时点 6 文件、最终交付 4 文件」）。

### 6.2 【建议】末尾【未坐实边界说明】未逐字覆盖过程文档的全部细项未坐实

过程文档 B/C 的「未坐实项」中以下细项在 spec 末尾【未坐实边界说明】未逐字列出（虽在 §3.5/正文部分已间接体现）：
- P2 的「`mp_maxid` 实际取值」未压测（B §未坐实项第 2 条）；
- P4 的「未逐协议排查 `.nh_dispatch` 是否都缺省 DEFAULT（仅确认 IP）」及「`swi_sched` 空 stub 是否被早期版本有意依赖」（C §未坐实项第 2/3 条）；
- P5 的「`rte_vlog` 内部线程安全未逐行核验」（B §未坐实项第 1 条）。

其中 P3 的「RACK/BBR 是否默认启用」已在 §3.5 P3 立项「前置确认」覆盖。上述遗漏属「完整性」瑕疵而非「诚实性」错误（spec 未将任何一项未坐实写成已验证），但为做到「完整保留所有未坐实项」，建议在末尾【未坐实边界说明】补全这几条。

### 6.3 【提示，可不改】第 1 行 `# 18-遗留风险专项处理`

文档主标题用了 Markdown `#`。正文标题全部为编号式（符合「编号标题、非 #」要求），且与团队全部过程文档（A/B/C/D/E/F/G/plan 均以 `# 主标题` 开头）风格一致，属文档主标题惯例，不构成违规，仅提示。

---

## 7. 结论

**PASS-with-fixes**。

- 审核项 1（事实一致性）：PASS —— 4 文件 diff 与 spec 完全一致，P6 纯文档化（`ff_thread.c` 无 diff、symlist 无 pcpup）坐实，关键 file:line 与数据点（error 0/warning 51、4/4、hpts=2、T1/T2/T3）全部实测吻合，无臆造/夸大/翻转。
- 审核项 2（裁决表述）：PASS —— P1/P3 独立立项、P6 纯文档化与 leader 决策一致，汇总表准确。
- 审核项 3（真实 IP）：PASS —— 全文 0 命中。
- 审核项 4（诚实边界）：PASS —— 主要未坐实项已保留，无翻转（细项完整性见 §6.2 建议）。
- 审核项 5（写作风格）：PASS —— 编号标题、无生硬小标题/客套/emoji。

无硬伤、无需 bounce。§6 所列 3 项均为建议级修正（非事实错误），可由 doc-writer 顺带优化，不影响结论定性为通过。
