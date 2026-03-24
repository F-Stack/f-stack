# 评审diff — 单一评审发现的问题记录

> 本文档记录仅由 1 个评审模型（共 3 个）提出的问题。这些问题未被其他评审交叉确认，供后续逐项验证和决策参考。

---

## 1. Claude-code-opus-4.6 独立发现 (11 项)

### C1: ff_config.h 行数标注错误

- **来源**: Claude §3.2
- **位置**: `F-Stack_Architecture_Layer2_Interface_Specification.md:304`
- **文档声明**: `ff_config.h (2855 行) - 配置接口`
- **实际情况**: `lib/ff_config.h` 实际为 **352 行**。2855 是 `ff_dpdk_if.c` 的行数，属于文件名与行数搞混的笔误。
- **影响**: 误导开发者对配置系统规模的判断。
- **建议修正**: 将 `2855` 改为 `352`。

### C2: ff_api.h 行数偏差

- **来源**: Claude §3.3
- **位置**: 多处引用 `ff_api.h (412 行)`
- **实际情况**: `lib/ff_api.h` 实际为 **416 行**，偏差 4 行。
- **影响**: 较小，说明行数快照未随代码变更同步。
- **建议修正**: 更新为实际行数，或标注"以源码为准"。

### C3: lib/Makefile 行数偏差

- **来源**: Claude §3.4
- **位置**: `01-LAYER1-ARCHITECTURE.md:91` 附近
- **文档声明**: `Makefile (264行) # 编译系统`
- **实际情况**: `lib/Makefile` 实际为 **765 行**，偏差接近 3 倍。
- **影响**: 中等，可能统计的是某个精简版本或只统计了非空行。
- **建议修正**: 更新为实际行数。

### C4: EVFILT_READ/WRITE 宏定义值错误

- **来源**: Claude §3.6
- **位置**: `03-LAYER3-FUNCTIONS.md` (简化L3) 和 `F-Stack_Architecture_Layer3_Function_Index.md` (完整L3)
- **文档声明**:
  - 简化版: `EVFILT_READ 0, EVFILT_WRITE 1`
  - 完整版: `EVFILT_READ 1, EVFILT_WRITE 2`
- **实际情况** (`lib/ff_event.h:39`):
  ```c
  #define EVFILT_READ     (-1)
  #define EVFILT_WRITE    (-2)
  ```
  FreeBSD kqueue 的 EVFILT 常量全部是**负值**。文档中两个版本都给出了不同的正值，均为错误。
- **影响**: 作为函数级索引文档，宏定义值错误会破坏参考手册的可靠性。
- **建议修正**: 统一改为负值 `(-1)` / `(-2)` 等。

### C5: ff_errno 值不一致

- **来源**: Claude §3.7
- **位置**: `F-Stack_Architecture_Layer2_Interface_Specification.md` (完整L2) 和 `03-LAYER3-FUNCTIONS.md` (简化L3)
- **文档声明**:
  - 完整L2: `ECONNREFUSED = 111` (Linux 标准)
  - 简化L3: `ECONNREFUSED = 61` (FreeBSD 标准)
- **实际情况** (`lib/ff_errno.h:100`):
  ```c
  #define ff_ECONNREFUSED 61 /* Connection refused */
  ```
  F-Stack 使用 FreeBSD 值 (61)，不是 Linux 值 (111)。
- **影响**: 完整L2 给出了错误的 errno 值，会直接误导调试过程。ETIMEDOUT 也存在类似问题 (文档 110 vs 实际 60)。
- **建议修正**: 统一使用 FreeBSD 标准值。

### C6: ff_kqueue 参数个数错误

- **来源**: Claude §3.8
- **位置**: `03-LAYER3-FUNCTIONS.md:49` 函数索引表
- **文档声明**: `ff_kqueue | BSD 事件队列 | 1 | int(kq_fd)`
- **实际情况** (`lib/ff_api.h:137`):
  ```c
  int ff_kqueue(void);
  ```
  参数个数为 **0** (void)，不是 1。完整L3 中正确写了 `ff_kqueue(void)`。
- **影响**: 简化版的函数索引表与实际声明不一致。
- **建议修正**: 将参数个数改为 `0`，返回值说明改为 `int(kq_fd)` 保持不变。

### C7: LD_PRELOAD + libfstack.so 描述与实际不符

- **来源**: Claude §4.2
- **位置**: `F-Stack_Architecture_Layer1_System_Overview.md:748-759` 和 `F-Stack_Knowledge_Base_Summary.md:215`
- **文档声明**: 描述了 `LD_PRELOAD=libfstack.so nginx` 的集成方式
- **实际情况**: 仓库中只生成 `libfstack.a`（静态库），Makefile 中没有共享库构建目标。Nginx 集成实际是通过修改源码 (`app/nginx-1.28.0/src/event/modules/ngx_ff_module.c`) 实现，而非 LD_PRELOAD 劫持。
- **影响**: 误导读者以为可以通过 LD_PRELOAD 方式使用 F-Stack。
- **建议修正**: 注明当前仅有静态库，Nginx 集成方式为源码修改。LD_PRELOAD 方式虽技术上可行但需额外构建 .so。
- **补充说明**: 在之前的 issue 处理中 (#400) 已确认 LD_PRELOAD 功能已经支持，此处描述可能需要进一步确认最新状态。

### C8: "10亿并发连接" 孤立错误数字

- **来源**: Claude §4.3
- **位置**: `01-LAYER1-ARCHITECTURE.md:333` (原文)
- **说明**: 此问题已在 Category B (B6) 中修正 — "10亿" 已改为 "1000万"。
- **交叉引用**: 见 B6 修改。

### C9: RACK 误分类为拥塞控制算法

- **来源**: Claude §6.3
- **位置**: `F-Stack_Architecture_Layer2_Interface_Specification.md:1123` 附近
- **文档声明**: 将 RACK (Recent ACKnowledgment) 放在 `net.inet.tcp.cc.algorithm` 的配置选项中
- **实际情况**: RACK 是**丢包检测机制**，不是拥塞控制算法。拥塞控制算法是 CUBIC/BBR 等。RACK 控制丢包判定方式，与 cc.algorithm 正交。
- **影响**: 可能误导开发者在配置文件中写出无效配置。
- **建议修正**: 从 cc.algorithm 选项列表中移除 RACK，改为独立说明其作为丢包检测机制的角色。

### C10: 缺少 HPTS 配置参数说明

- **来源**: Claude §6.4
- **说明**: `config.ini` 中包含 `net.inet.tcp.hpts.skip_swi=1`、`minsleep=250` 等 HPTS (High Precision Timer System) 参数，但文档配置系统分析中完全未涉及。
- **影响**: HPTS 参数对 RACK/BBR 性能有直接影响，且与 issue #701/#702 中 tcp_hpts.h 变更相关。
- **建议修正**: 在配置系统分析部分补充 HPTS 相关参数说明。

### C11: 文档使用大量 emoji

- **来源**: Claude §6.5
- **位置**: `README.md` 中使用 emoji 作为段落标记，`F-Stack_Knowledge_Base_Summary.md` 和 `SUMMARY.txt` 中也有类似用法
- **影响**: 在纯文本环境、终端工具或 PDF 导出场景下可能显示为乱码。
- **建议处理**: 对于长期维护的工程文档，可考虑用纯文本标记替代，但当前不影响 GitHub 渲染。

---

## 2. Gemini-3.1-Pro 独立发现 (2 项)

### C12: ASCII 图表局限性

- **来源**: Gemini §3.2
- **说明**: 架构图和数据流图全部采用 ASCII 纯文本绘制，在表达复杂的多进程通信或内存池映射关系时表现力不足。
- **建议**: 使用 Mermaid.js 语法替代部分复杂 ASCII 图表，可在 GitHub 原生 Markdown 平台上良好渲染。
- **评估**: 改进建议合理，但当前 ASCII 图表兼容性更好，可在后续迭代中逐步引入。

### C13: 建议 Doxygen 自动化 API 文档

- **来源**: Gemini §4 item 4
- **说明**: Layer 3 中的函数索引由于源码迭代可能导致行数或参数频繁变化，建议引入 Doxygen 等注释规范，通过脚本自动同步源码到 Markdown 文档。
- **评估**: 长期有价值，短期实施成本较高。可作为后续优化方向纳入规划。

---

## 3. Claude-code-opus-4.6 独立发现 — 结构性问题 (1 项)

### C14: ff_config 结构体与实际代码偏差

- **来源**: Claude §4.4
- **位置**: `F-Stack_Architecture_Layer2_Interface_Specification.md:306-357` 和 `F-Stack_Architecture_Layer3_Function_Index.md:568-621`
- **说明**: 两份文档都给出了 `struct ff_config` 的定义，但两者字段不完全相同，且都是文档作者根据理解重构的"概要版"，与 `lib/ff_config.h` 中的实际定义存在差异（实际字段更多、嵌套更深）。
- **影响**: 作为接口规范文档，不精确的结构体定义可能误导开发者。
- **建议修正**: 标注"以 ff_config.h 为准"，或删除不准确的结构体定义，仅列出关键字段。

---

## 统计摘要

| 类别 | 数量 | 来源 |
|------|------|------|
| Claude 独立发现 | 11 项 (C1-C11) | Claude-code-opus-4.6 评审 |
| Gemini 独立发现 | 2 项 (C12-C13) | Gemini-3.1-Pro 评审 |
| Claude 结构性问题 | 1 项 (C14) | Claude-code-opus-4.6 评审 |
| **合计** | **14 项** | |

> 其中 C8 已在正式修改中处理 (见 Category B - B6 修改)。
