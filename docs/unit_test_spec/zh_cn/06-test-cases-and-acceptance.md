# 06 — 测试用例与验收标准

> 文档版本：v0.1（2026-06-09 18:05 UTC+8）
> Author：spec-author
> 适用范围：F-Stack lib/ FF_HOST_SRCS P0 / P1 测试用例草案 + 验收标准 + 覆盖率目标

---

## 1. 文档目的与命名规范

本 spec 列出本任务（spec 阶段）中：(1) P0 文件（ff_ini_parser.c + ff_log.c）的 **TC-U-\*** 测试用例草案 ≥ 20 条；(2) P1 文件（ff_host_interface.c + ff_epoll.c + ff_config.c）用例概览 ≥ 18 条；(3) 边界覆盖矩阵；(4) 覆盖率目标；(5) 验收标准。

### 1.1 TC-U-* 用例 ID 编号规则

```
TC-U-<P0|P1|P2>-<file_short>-<seq>
            示例：
            TC-U-P0-INI-01    ← ff_ini_parser.c 第 1 个用例
            TC-U-P0-LOG-03    ← ff_log.c 第 3 个用例
            TC-U-P1-HIF-02    ← ff_host_interface.c 第 2 个用例
```

| 缩写 | 文件 |
|---|---|
| INI | ff_ini_parser.c |
| LOG | ff_log.c |
| HIF | ff_host_interface.c |
| EPL | ff_epoll.c |
| CFG | ff_config.c |

### 1.2 测试函数命名（FR-U-7）

`test_<被测函数名>_<场景>(void **state)` —— 必须以 `test_` 开头，函数名段去掉 `ff_` 前缀简化。

示例：
- `test_ini_parse_stream_valid_basic` — ff_ini_parser.c 中 `ini_parse_stream` 的"基础有效输入"场景
- `test_ff_log_open_set_dir_not_exist` — ff_log.c 中 `ff_log_open_set` 在 dir 不存在时的场景
- `test_ff_load_config_minimal_valid_ini` — ff_config.c 中 `ff_load_config` 端到端最小有效 ini 场景

---

## 2. P0 ff_ini_parser.c 测试用例（≥10 条）

### 2.1 被测 API（详 spec 02 §3.3）

| API | 主要逻辑 |
|---|---|
| `ini_parse_stream(ini_reader reader, void* stream, ini_handler handler, void* user)` | 状态机核心 |
| `ini_parse_file(FILE* file, ini_handler handler, void* user)` | wrap 标准 fgets |
| `ini_parse(const char* filename, ini_handler handler, void* user)` | wrap fopen + ini_parse_file |

### 2.2 用例清单

| TC-ID | 用例名 | 测试 API | 输入 | 期望输出 | 覆盖目标 |
|---|---|---|---|---|---|
| **TC-U-P0-INI-01** | `test_ini_parse_stream_valid_basic` | ini_parse_stream | `[s1]\\nkey=value\\n` | 返回 0；handler 被调用 1 次，section="s1", name="key", value="value" | 基础有效路径 |
| **TC-U-P0-INI-02** | `test_ini_parse_stream_multiple_sections` | ini_parse_stream | 2 section × 2 key | 返回 0；handler 被调用 4 次，每次 section/name/value 准确 | 多 section 切换 |
| **TC-U-P0-INI-03** | `test_ini_parse_stream_comment_lines` | ini_parse_stream | `; comment\\n# comment\\n[s1]\\nk=v` | 返回 0；handler 仅被调用 1 次（comment 被跳过）| comment 跳过 |
| **TC-U-P0-INI-04** | `test_ini_parse_stream_inline_comment` | ini_parse_stream | `[s1]\\nk=v ; inline` | 返回 0；handler value="v"（去 inline comment）| inline comment 处理 |
| **TC-U-P0-INI-05** | `test_ini_parse_stream_whitespace_strip` | ini_parse_stream | `[s1]\\n  k  =  v  \\n` | name="k", value="v"（前后空白去除）| rstrip / lskip |
| **TC-U-P0-INI-06** | `test_ini_parse_stream_empty_value` | ini_parse_stream | `[s1]\\nk=\\n` | name="k", value=""（空值合法）| 空值边界 |
| **TC-U-P0-INI-07** | `test_ini_parse_stream_no_section` | ini_parse_stream | `k=v` | 返回 1（首行错误，未在 section 内）| 错误恢复（section 缺失）|
| **TC-U-P0-INI-08** | `test_ini_parse_stream_invalid_syntax` | ini_parse_stream | `[s1]\\ninvalid_no_eq` | 返回 2（第 2 行错误）| 错误恢复（无 = 号）|
| **TC-U-P0-INI-09** | `test_ini_parse_stream_handler_returns_zero` | ini_parse_stream | 任意有效 + handler 返回 0 | ini_parse_stream 返回非 0（handler 报错）| handler 中止 |
| **TC-U-P0-INI-10** | `test_ini_parse_stream_bom_utf8` | ini_parse_stream | `\\xEF\\xBB\\xBF[s1]\\nk=v` | 返回 0（BOM 被跳过）| BOM 处理 |
| **TC-U-P0-INI-11** | `test_ini_parse_file_normal` | ini_parse_file | 临时 FILE\* 含 2 行 | 返回 0；handler 被调用准确次数 | FILE\* 入口 |
| **TC-U-P0-INI-12** | `test_ini_parse_file_null` | ini_parse_file | NULL FILE\* | 返回 -1 或 SIGSEGV（spec 中决定行为；建议 wrap fgets 捕获）| NULL 防御 |
| **TC-U-P0-INI-13** | `test_ini_parse_filename_not_exist` | ini_parse | `/nonexistent.ini` | 返回 -1 | fopen 失败路径 |
| **TC-U-P0-INI-14** | `test_ini_parse_filename_normal` | ini_parse | 临时文件路径 | 返回 0；handler 被调用准确次数 | filename 入口 |
| **TC-U-P0-INI-15** | `test_ini_parse_stream_long_section_name` | ini_parse_stream | section 名 60 字符（> MAX_SECTION 50）| section 名截断到 50 | MAX_SECTION 边界 |
| **TC-U-P0-INI-16** | `test_ini_parse_stream_long_key_name` | ini_parse_stream | key 名 60 字符（> MAX_NAME 50）| key 名截断到 50 | MAX_NAME 边界 |
| **TC-U-P0-INI-17** | `test_ini_parse_stream_user_data_passed` | ini_parse_stream | user=自定义 struct 指针 | handler 收到的 user 与传入相同 | user 透传 |
| **TC-U-P0-INI-18** | `test_ini_parse_stream_zero_byte_input` | ini_parse_stream | 空 stream | 返回 0；handler 不被调用 | 空输入 |

**总计 P0-INI 用例：18 条**（FR-U-6 阈值 ≥10 ✓）

### 2.3 关键 fixture 设计

```c
/* test_ff_ini_parser.c */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>
#include "ff_ini_parser.h"

/* Capture handler invocations via cmocka mock() */
static int capture_handler(void *user, const char *section,
                           const char *name, const char *value) {
    check_expected_ptr(section);   /* expect_string 验证 */
    check_expected_ptr(name);
    check_expected_ptr(value);
    return mock_type(int);          /* will_return 推入 1 表示成功 */
}

/* Helper: parse a string buffer */
static int parse_buf(const char *buf, ini_handler h, void *user) {
    FILE *f = fmemopen((void *)buf, strlen(buf), "r");
    int rv = ini_parse_file(f, h, user);
    fclose(f);
    return rv;
}
```

---

## 3. P0 ff_log.c 测试用例（≥10 条）

### 3.1 被测 API（详 spec 02 §3.4）

7 个公开 API + ff_global_cfg.log.* 全局依赖。

### 3.2 必备公共 stub（详 spec 04 §9）

`common/ff_log_stub.{c,h}` 提供 `struct ff_config_stub ff_global_cfg`。

### 3.3 用例清单

| TC-ID | 用例名 | 测试 API | 输入 | 期望 | 覆盖目标 |
|---|---|---|---|---|---|
| **TC-U-P0-LOG-01** | `test_ff_log_open_set_normal` | ff_log_open_set | dir="/tmp/", proc_id=0 | 返回 0；ff_global_cfg.log.f 非 NULL；rte_openlog_stream 被调用 1 次 | 正常路径 |
| **TC-U-P0-LOG-02** | `test_ff_log_open_set_dir_invalid` | ff_log_open_set | dir="/nonexistent/xyz/" | 返回 ≠ 0；ff_global_cfg.log.f == NULL | fopen 失败 |
| **TC-U-P0-LOG-03** | `test_ff_log_open_set_long_filename` | ff_log_open_set | dir 长度 200 字符 | 文件名构造正确（filename 字段无 truncate）| 字符串拼接 |
| **TC-U-P0-LOG-04** | `test_ff_log_close_when_open` | ff_log_close | log.f 非 NULL（前置 fopen tmpfile）| log.f 被置 NULL；fclose 被调用 | 资源回收 |
| **TC-U-P0-LOG-05** | `test_ff_log_close_when_null` | ff_log_close | log.f == NULL | 不崩；log.f 仍 NULL | NULL 防御 |
| **TC-U-P0-LOG-06** | `test_ff_log_reset_stream_normal` | ff_log_reset_stream | f=tmpfile() | 返回 0；__wrap_rte_openlog_stream 被调用 1 次，参数 == f | rte_ wrap |
| **TC-U-P0-LOG-07** | `test_ff_log_set_global_level` | ff_log_set_global_level | level=7 | __wrap_rte_log_set_global_level 被调用，参数 == 7 | rte_ wrap |
| **TC-U-P0-LOG-08** | `test_ff_log_set_level_normal` | ff_log_set_level | logtype=1, level=7 | __wrap_rte_log_set_level 被调用 (logtype, level) | rte_ wrap |
| **TC-U-P0-LOG-09** | `test_ff_log_set_level_returns_value` | ff_log_set_level | rte_log_set_level wrap 返回 -1 | ff_log_set_level 返回 -1（透传）| 返回值透传 |
| **TC-U-P0-LOG-10** | `test_ff_log_variadic_basic` | ff_log | level=7, logtype=1, fmt="x=%d", args=42 | __wrap_rte_vlog 被调用 1 次；args 经 va_start 正确 | 变参 + va_start/end |
| **TC-U-P0-LOG-11** | `test_ff_log_variadic_zero_args` | ff_log | fmt="static msg" | __wrap_rte_vlog 被调用 1 次；fmt 透传准确 | 0 args 边界 |
| **TC-U-P0-LOG-12** | `test_ff_vlog_normal` | ff_vlog | level, logtype, fmt, va_list ap | __wrap_rte_vlog 被调用 1 次，全参透传 | va_list 直传 |
| **TC-U-P0-LOG-13** | `test_ff_log_returns_rte_vlog_value` | ff_log | __wrap_rte_vlog 返回 5 | ff_log 返回 5 | 返回值透传 |

**总计 P0-LOG 用例：13 条**（FR-U-6 阈值 ≥10 ✓）

### 3.4 关键 wrap 实现

```c
/* In test_ff_log.c */
int __wrap_rte_openlog_stream(FILE *f) {
    check_expected_ptr(f);
    return mock_type(int);
}

void __wrap_rte_log_set_global_level(uint32_t level) {
    check_expected(level);
}

int __wrap_rte_log_set_level(uint32_t logtype, uint32_t level) {
    check_expected(logtype);
    check_expected(level);
    return mock_type(int);
}

int __wrap_rte_vlog(uint32_t level, uint32_t logtype, const char *fmt, va_list ap) {
    (void)ap;   /* don't dereference, only verify level/logtype/fmt fingerprint */
    check_expected(level);
    check_expected(logtype);
    check_expected_ptr(fmt);
    return mock_type(int);
}
```

---

## 4. P1 用例草案概览（≥18 条）

### 4.1 ff_host_interface.c TC 草案（≥6 条）

| TC-ID | 用例名 | 覆盖 API | 关键点 |
|---|---|---|---|
| **TC-U-P1-HIF-01** | `test_ff_malloc_normal` | ff_malloc | __wrap_rte_malloc 被调用 |
| **TC-U-P1-HIF-02** | `test_ff_calloc_zeros_memory` | ff_calloc | 返回值 zero-filled |
| **TC-U-P1-HIF-03** | `test_ff_realloc_grow` | ff_realloc | __wrap_rte_realloc 被调用 |
| **TC-U-P1-HIF-04** | `test_ff_free_null` | ff_free | NULL 不崩 |
| **TC-U-P1-HIF-05** | `test_ff_clock_gettime_monotonic` | ff_clock_gettime | 返回值 ≥ 上次值 |
| **TC-U-P1-HIF-06** | `test_ff_arc4rand_buf_filled` | ff_arc4rand | buf 被填充非全 0 |
| **TC-U-P1-HIF-07** | `test_ff_get_current_time_advances` | ff_get_current_time | 多次调用值递增 |
| **TC-U-P1-HIF-08** | `test_ff_os_errno_mapping` | ff_os_errno | errno 映射准确 |

**TC-U-P1-HIF 总数：8** ✓

### 4.2 ff_epoll.c TC 草案（≥6 条）

| TC-ID | 用例名 | 覆盖 API | 关键点 |
|---|---|---|---|
| **TC-U-P1-EPL-01** | `test_ff_epoll_create_returns_fd` | ff_epoll_create | size 参数被忽略；返回 fd |
| **TC-U-P1-EPL-02** | `test_ff_epoll_ctl_add_event` | ff_epoll_ctl | EPOLL_CTL_ADD → ff_kevent EV_ADD |
| **TC-U-P1-EPL-03** | `test_ff_epoll_ctl_del_event` | ff_epoll_ctl | EPOLL_CTL_DEL → ff_kevent EV_DELETE |
| **TC-U-P1-EPL-04** | `test_ff_epoll_ctl_mod_event` | ff_epoll_ctl | EPOLL_CTL_MOD → 逻辑映射准确 |
| **TC-U-P1-EPL-05** | `test_ff_epoll_wait_event_translation` | ff_epoll_wait | EVFILT_READ → EPOLLIN |
| **TC-U-P1-EPL-06** | `test_ff_epoll_wait_zero_timeout` | ff_epoll_wait | timeout=0 路径 |
| **TC-U-P1-EPL-07** | `test_ff_epoll_wait_invalid_args` | ff_epoll_wait | maxevents ≤ 0 → -1 / EINVAL |

**TC-U-P1-EPL 总数：7** ✓

### 4.3 ff_config.c TC 草案（≥10 条，端到端为主）

| TC-ID | 用例名 | 覆盖 API | 关键点 |
|---|---|---|---|
| **TC-U-P1-CFG-01** | `test_ff_load_config_valid_minimal_ini` | ff_load_config | fixtures/valid_minimal.ini → ff_global_cfg.dpdk.lcore_mask 等准确 |
| **TC-U-P1-CFG-02** | `test_ff_load_config_no_dpdk_section` | ff_load_config | fixtures/invalid_no_dpdk.ini → 返回错误 |
| **TC-U-P1-CFG-03** | `test_ff_load_config_invalid_lcore_mask` | ff_load_config | fixtures/invalid_bad_lcore.ini → 返回错误 / 提示 |
| **TC-U-P1-CFG-04** | `test_ff_load_config_dual_vlan` | ff_load_config | fixtures/valid_dual_vlan.ini → ff_global_cfg.vlan[0/1] 各字段准确 |
| **TC-U-P1-CFG-05** | `test_ff_load_config_with_vip_addr` | ff_load_config | vip_addr=192.169.0.10,11 → 解析正确 |
| **TC-U-P1-CFG-06** | `test_ff_load_config_argv_override` | ff_load_config | argv "-c /tmp/x.ini --proc-type=primary" → 解析准确 |
| **TC-U-P1-CFG-07** | `test_ff_load_config_unknown_section` | ff_load_config | ini 含 [unknown] → 警告但不崩 |
| **TC-U-P1-CFG-08** | `test_ff_load_config_empty_ini` | ff_load_config | 空 ini → 返回错误 |
| **TC-U-P1-CFG-09** | `test_vlan_cfg_handler_isolated`（白盒）| `#include "ff_config.c"` | 直接调 vlan_cfg_handler，验证 ff_vlan_cfg 字段 |
| **TC-U-P1-CFG-10** | `test_ipfw_pr_cfg_handler_isolated`（白盒）| 同上 | ipfw_pr_cfg_handler 解析 fib + cidr |
| **TC-U-P1-CFG-11** | `test_port_cfg_handler_addr_parse` | 同上 | port_cfg_handler addr=9.134.214.176/21 解析 |

**TC-U-P1-CFG 总数：11** ✓

---

## 5. 边界覆盖矩阵（FR-U-8）

| 边界类型 | P0 文件覆盖 | P1 文件覆盖 |
|---|---|---|
| **空输入** | TC-U-P0-INI-18 (空 stream) / TC-U-P0-LOG-11 (0 args) | TC-U-P1-CFG-08 (空 ini) |
| **极端长度** | TC-U-P0-INI-15/16 (长 section/key) / TC-U-P0-LOG-03 (长 dir)| TC-U-P1-HIF-03 (大 alloc) |
| **非法字符** | TC-U-P0-INI-08 (无 = 号) / TC-U-P0-INI-07 (无 section) | TC-U-P1-CFG-03 (非法 lcore_mask) |
| **NULL 指针** | TC-U-P0-INI-12 (NULL FILE\*) / TC-U-P0-LOG-05 (NULL log.f close) | TC-U-P1-HIF-04 (NULL free) |
| **重复 key** | （leave 阶段三补）| TC-U-P1-CFG-07 (unknown section) |
| **资源失败路径** | TC-U-P0-INI-13 (fopen 失败) / TC-U-P0-LOG-02 (dir 不存在) | — |

**5 类边界 ≥ 5 行 ✓**（FR-U-8 阈值）

---

## 6. 覆盖率目标（NFR-U-2 + DP-U-B4）

### 6.1 阈值（spec 阶段列出，阶段三接入工具）

| 优先级 | 文件 | 行覆盖 | 分支覆盖 | 阶段 |
|---|---|---|---|---|
| **P0** | ff_ini_parser.c | ≥80% | ≥70% | 阶段三必达 |
| **P0** | ff_log.c | ≥80% | ≥70% | 阶段三必达 |
| **P1** | ff_host_interface.c | ≥60% | ≥50% | 阶段四必达 |
| **P1** | ff_epoll.c | ≥60% | ≥50% | 阶段四必达 |
| **P1** | ff_config.c | ≥50%（端到端覆盖率天然有限）| ≥40% | 阶段四必达 |
| **P2/P3** | 其他 6 文件 | 不强求 | 不强求 | follow-up |

### 6.2 工具链（阶段三引入，本 spec 阶段不接入）

- `gcov` — 编译期 instrumentation（spec 04 §6.2 已列 flags）
- `lcov` — 收集 .gcda 生成 HTML 报告
- `gcovr` — XML 报告（CI 友好）

---

## 7. 验收标准（与 spec 01 §6 同步）

### 7.1 spec 阶段验收（本任务范围）

| Gate | 检查 | PASS 条件 |
|---|---|---|
| **G1 spec 落盘** | `ls docs/unit_test_spec/zh_cn/` ≥ 7 markdown | 7 篇全部存在 |
| **G2 cross-check** | gate-keeper 抽样 ≥10 处 line 引用实测 | 100% 命中 |
| **G3 4 维评分** | 一致性 / 完整性 / 风险覆盖度 / 可执行性 | 全 ≥ A |
| **G4 compliance** | grep 直接 rm/kill/chmod | 0 命中 |
| **G5 用例数下限** | P0 ≥ 20 + P1 ≥ 18 | 实际 P0=31 / P1=26（G5 PASS）|

### 7.2 阶段二/三验收（仅 spec 中列，本阶段不执行）

| Gate | 检查 | PASS 条件 |
|---|---|---|
| **G6 阶段二 build** | `cd tests/unit && make` | exit=0 / 0 errors |
| **G7 阶段三 P0 全 PASS** | `make test` 跑 ≥31 个 P0 TC | 100% PASS / 总耗时 < 3s |
| **G8 阶段三覆盖率** | `make coverage` 生成 .gcov | P0 行覆盖 ≥80% / 分支 ≥70% |
| **G9 阶段四 P1 全 PASS** | `make test` 跑 ≥26 个 P1 TC | 100% PASS / 总耗时 < 30s |
| **G10 阶段五 CI** | GitHub Actions / 内部 CI 集成 | 每 PR 自动跑 P0+P1 全套 |

---

## 8. 跑测命令（spec 描述，阶段二落地）

```bash
# 切到测试目录
cd /data/workspace/f-stack/tests/unit

# 默认（仅 build + run，不含 valgrind / coverage）
make test

# 含 valgrind
make check

# 含覆盖率
make coverage

# 仅 build 不 run
make all

# 清理（用 wrapper，per NFR-U-7）
make clean
```

---

## 9. 用例总数汇总

| 优先级 | 文件 | 用例数 | 阶段 |
|---|---|---|---|
| **P0** | ff_ini_parser.c | 18 | 阶段三 |
| **P0** | ff_log.c | 13 | 阶段三 |
| **P1** | ff_host_interface.c | 8 | 阶段四 |
| **P1** | ff_epoll.c | 7 | 阶段四 |
| **P1** | ff_config.c | 11 | 阶段四 |
| **P0+P1 小计** | 5 文件 | **57** | — |
| **P2 follow-up** | 5 文件 | 待估 | 阶段五 |
| **P3 暂不测** | 1 文件（ff_memory.c）| 0 | — |

→ **FR-U-6 阈值 ≥25**：P0+P1 共 **57** 条 ✓

---

## 10. 与 c-unittest-expert.mdc 方法论对照

| 方法论原则 | 落实位置 |
|---|---|
| 测试命名 `test_<func>_<scenario>` | §1.2 + §2.2 / §3.3 / §4.x 全部用例命名 |
| 边界覆盖 5 类（empty / extreme / illegal / NULL / 失败路径）| §5 矩阵 |
| Setup/teardown 隔离 | §2.3 + §3.4 fixture 模板 |
| 1 测试只验 1 行为 | 每条 TC 仅 1 个 expected outcome |
| 断言粒度细化 | 用 `assert_int_equal` / `assert_string_equal` / `assert_non_null` 区分类型 |
| Mock 边界清晰 | spec 04 §7 矩阵 + 本文件 §3.4 wrap 实现 |

---

## 11. 阶段三落地 checklist（spec 阶段不执行，仅列）

- [ ] 落 `tests/unit/test_ff_ini_parser.c`（含 18 TC）
- [ ] 落 `tests/unit/test_ff_log.c`（含 13 TC）
- [ ] 落 `tests/unit/fixtures/valid_minimal.ini` 等 4-6 个 ini fixture（备 P1 用）
- [ ] `make test` 通过 31/31 P0
- [ ] `make coverage` 达 P0 行覆盖 ≥80%

---

**文档结束（v0.1，450 行预算内）**
