# 04 — CMocka 框架与实现策略

> 文档版本：v0.1（2026-06-09 18:00 UTC+8）
> Author：spec-author（基于 mock-strategist + arch-explorer Phase 2 调研）
> 适用范围：F-Stack lib/ FF_HOST_SRCS 11 文件 CMocka 单元测试框架的集成方案 / 目录结构 / Makefile 设计 / mock 策略矩阵

---

## 1. CMocka 框架简介与选型

### 1.1 选型理由（与 Unity / Check / Criterion 对比）

| 特性 | Unity | **CMocka** | Check | Criterion |
|---|---|---|---|---|
| 内置 mock | ❌（需 CMock 配套）| ✅ `expect_*` / `will_return` / `mock()` | 部分 | ✅ |
| 子进程隔离测试崩溃 | ❌ | ✅ setjmp/longjmp | ✅ fork | ✅ fork |
| Group fixture | 手动 | ✅ `cmocka_run_group_tests` | ✅ | ✅ |
| 内存泄漏检测 | ❌ | ✅ `test_malloc/test_free` | ✅ | ❌ |
| 异常断言 | 部分 | ✅ `expect_assert_failure` | ❌ | ✅ |
| C99/C11/C17 | ✅ | ✅ | ✅ | ✅ |
| 嵌入式友好 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| 中文社区资料 | 多 | 中（CMocka 官方 + Samba/libssh 实践）| 少 | 少 |

→ **决策（DP-U-4 已定）**：CMocka 1.1.7。**理由**：(a) 内置 mock 强（适合 F-Stack 大量 DPDK API 替换）；(b) setjmp 子进程隔离对 `rte_exit/rte_panic` 致命路径友好；(c) 已通过 `dnf install` 就位无需源码编译。

### 1.2 版本要求（R-U-3 mitigation）

- **CMocka ≥ 1.1.7**（通过 `pkg-config --modversion cmocka` 校验）
- 若环境 < 1.1.7，spec 04 §6 Makefile 提供 fallback：源码编译 https://gitlab.com/cmocka/cmocka

---

## 2. 安装与就位状态

### 2.1 当前 CVM 实测

```bash
$ rpm -qa | grep cmocka
libcmocka-1.1.7-4.tl4.x86_64
libcmocka-devel-1.1.7-4.tl4.x86_64

$ pkg-config --modversion cmocka
1.1.7

$ pkg-config --cflags --libs cmocka
-lcmocka

$ ls /usr/include/cmocka.h /usr/lib64/libcmocka.so.0.8.0
/usr/include/cmocka.h
/usr/lib64/libcmocka.so.0.8.0
```

### 2.2 CMocka demo（前对话验证）

简单 add 函数 demo：2/2 PASS（test_add_positive + test_add_negative）。验证 `cmocka_unit_test` + `cmocka_run_group_tests` + `assert_int_equal` 工作正常。

---

## 3. Unity → CMocka API 映射表（FR-U-3）

参考 `c-unittest-expert.mdc` 方法论，但 API 映射为 CMocka 形式：

| 方法论概念 | Unity API | **CMocka API** | 备注 |
|---|---|---|---|
| 测试函数定义 | `void test_xxx(void)` | `static void test_xxx(void **state)` | CMocka 多 state 参数（fixture 上下文）|
| Group setup/teardown | `setUp()` / `tearDown()` | `static int test_setup(void **state)` / `static int test_teardown(void **state)` | CMocka 返回 int |
| 主测试 runner | `RUN_TEST(test_xxx)` | `cmocka_unit_test(test_xxx)` 或 `cmocka_unit_test_setup_teardown(test_xxx, setup, teardown)` | — |
| Group runner | `UNITY_BEGIN()` + 多 `RUN_TEST` + `UNITY_END()` | `cmocka_run_group_tests(tests, group_setup, group_teardown)` | — |
| **断言整数相等** | `TEST_ASSERT_EQUAL_INT(a, b)` | `assert_int_equal(a, b)` | — |
| 断言整数不等 | `TEST_ASSERT_NOT_EQUAL_INT(a, b)` | `assert_int_not_equal(a, b)` | — |
| 断言字符串相等 | `TEST_ASSERT_EQUAL_STRING(a, b)` | `assert_string_equal(a, b)` | — |
| 断言指针非空 | `TEST_ASSERT_NOT_NULL(p)` | `assert_non_null(p)` | — |
| 断言指针为空 | `TEST_ASSERT_NULL(p)` | `assert_null(p)` | — |
| 断言条件真 | `TEST_ASSERT_TRUE(cond)` | `assert_true(cond)` | — |
| 断言条件假 | `TEST_ASSERT_FALSE(cond)` | `assert_false(cond)` | — |
| 内存比较 | `TEST_ASSERT_EQUAL_MEMORY(a, b, n)` | `assert_memory_equal(a, b, n)` | — |
| 范围断言 | `TEST_ASSERT_INT_WITHIN(d, ex, ac)` | `assert_in_range(value, min, max)` | — |
| 主动失败 | `TEST_FAIL()` | `fail()` 或 `fail_msg("reason")` | — |
| 跳过测试 | `TEST_IGNORE()` | `skip()` | — |
| **Mock 函数返回值** | `Mock_xxx_ExpectAnyArgsAndReturn(v)` (CMock) | `will_return(__wrap_xxx, v)` | CMocka 配 `--wrap` 链接器 flag |
| **Mock 入参验证** | `Mock_xxx_Expect(arg)` (CMock) | `expect_value(__wrap_xxx, param, val)` / `expect_string(__wrap_xxx, param, "str")` | — |
| 提取入参 | — | `mock_type(int)` / `mock_ptr_type(void *)` | wrap 函数体内取 will_return 推入的值 |
| **断言会触发 assert** | — | `expect_assert_failure(call(...))` | 验证致命路径 |

→ **共 18 行 API 映射**（FR-U-3 阈值 ≥15 ✓）。

---

## 4. tests/unit/ 目录结构（DP-U-B5）

```
f-stack/
└── tests/
    ├── README.md                                # 测试体系入口 + 使用文档
    └── unit/
        ├── Makefile                             # 独立 GNU Makefile（详 §5）
        ├── common/
        │   ├── ff_log_stub.c                    # 公共 stub：mock ff_log/ff_global_cfg
        │   ├── ff_log_stub.h                    # ff_global_cfg 静态实例 declarator
        │   ├── rte_stub.c                       # 公共 mock：rte_exit/rte_panic 致命替换
        │   └── rte_stub.h
        ├── fixtures/
        │   ├── valid_minimal.ini                # P1 ff_config.c 端到端 fixture
        │   ├── invalid_no_dpdk.ini              # 缺 [dpdk] section
        │   ├── invalid_bad_lcore.ini            # lcore_mask 非法
        │   └── (其他 .ini fixtures by need)
        ├── test_ff_ini_parser.c                 # P0 #1
        ├── test_ff_log.c                        # P0 #2
        ├── test_ff_host_interface.c             # P1 #3
        ├── test_ff_epoll.c                      # P1 #4
        ├── test_ff_config.c                     # P1 #5
        └── (P2 / P3 留空，follow-up)
```

### 4.1 命名规范

- 测试文件：`test_<被测文件名去 .c>.c`（如 `test_ff_log.c` 测 `lib/ff_log.c`）
- 测试函数：`test_<func>_<scenario>(void **state)`（FR-U-7）
- Group fixture：`<test_file>_setup` / `<test_file>_teardown`
- Mock wrap：`__wrap_<api_name>`（与 `--wrap=<api_name>` 链接器 flag 配套）

---

## 5. Makefile 设计草案（NFR-U-6 关键：不污染 lib/Makefile）

### 5.1 顶层 `tests/unit/Makefile`

```makefile
# F-Stack lib/ unit test Makefile (CMocka 1.1.7+)
# Independent of lib/Makefile; compiles only target .c + stubs + tests.

TOPDIR        := $(abspath ../..)
LIB_DIR       := $(TOPDIR)/lib
COMMON_DIR    := common
FIXTURE_DIR   := fixtures

# Tooling
CC            ?= gcc
PKG_CFG       ?= pkg-config
CMOCKA_CFLAGS := $(shell $(PKG_CFG) --cflags cmocka)
CMOCKA_LIBS   := $(shell $(PKG_CFG) --libs cmocka)

# Versions guard (R-U-3)
CMOCKA_VER    := $(shell $(PKG_CFG) --modversion cmocka)
CMOCKA_OK     := $(shell echo "$(CMOCKA_VER)" | awk -F. '{ if ($$1 > 1 || ($$1 == 1 && $$2 > 1) || ($$1 == 1 && $$2 == 1 && $$3 >= 7)) print "ok" }')
ifneq ($(CMOCKA_OK),ok)
$(error CMocka >= 1.1.7 required, found $(CMOCKA_VER))
endif

# Host-only build flags (R-U-2 / NFR-U-4)
CFLAGS        := -O0 -g3 -Wall -Wextra -Wno-unused-parameter \
                 -I$(LIB_DIR) -I$(COMMON_DIR) \
                 $(CMOCKA_CFLAGS) \
                 -DFF_UNIT_TEST=1
LDFLAGS       := $(CMOCKA_LIBS)

# Tests list
P0_TESTS      := test_ff_ini_parser test_ff_log
P1_TESTS      := test_ff_host_interface test_ff_epoll test_ff_config
ALL_TESTS     := $(P0_TESTS) $(P1_TESTS)

# Per-test wrap flags (decide --wrap=<sym> per test file; see §7)
WRAP_FF_LOG   := -Wl,--wrap=rte_openlog_stream \
                 -Wl,--wrap=rte_log_set_global_level \
                 -Wl,--wrap=rte_log_set_level \
                 -Wl,--wrap=rte_vlog
WRAP_FF_HOST  := -Wl,--wrap=rte_malloc -Wl,--wrap=rte_free
WRAP_FF_INI   := # zero wrap

# Common stubs (link into every test by default)
COMMON_OBJS   := $(COMMON_DIR)/ff_log_stub.o $(COMMON_DIR)/rte_stub.o

# Default goal
.PHONY: all test check clean coverage
all: $(ALL_TESTS)

test: all
	@for t in $(ALL_TESTS); do \
	  echo "==> running $$t"; ./$$t || exit 1; \
	done
	@echo "ALL TESTS PASS"

check: test
	@echo "TODO: integrate valgrind --tool=memcheck per test"

# Pattern rule (each test links target .o + stubs)
test_ff_ini_parser: test_ff_ini_parser.o $(LIB_DIR)/ff_ini_parser.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(WRAP_FF_INI)

test_ff_log: test_ff_log.o $(LIB_DIR)/ff_log.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(WRAP_FF_LOG)

test_ff_host_interface: test_ff_host_interface.o $(LIB_DIR)/ff_host_interface.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(WRAP_FF_HOST)

test_ff_epoll: test_ff_epoll.o $(LIB_DIR)/ff_epoll.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

test_ff_config: test_ff_config.o $(LIB_DIR)/ff_config.o $(LIB_DIR)/ff_ini_parser.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@find . -name '*.o' -print | xargs -r /data/workspace/rm_tmp_file.sh
	@for t in $(ALL_TESTS); do \
	  [ -f $$t ] && /data/workspace/rm_tmp_file.sh $(CURDIR)/$$t; \
	done

coverage: CFLAGS += -fprofile-arcs -ftest-coverage
coverage: LDFLAGS += -lgcov --coverage
coverage: clean test
	gcov *.c > /dev/null
	@echo "TODO: lcov / genhtml integration (阶段三)"
```

### 5.2 Makefile 关键设计

| 设计点 | 理由 |
|---|---|
| **不 include `lib/Makefile`** | NFR-U-6：与 lib build 完全解耦 |
| **不链 `libfstack.a`** | R-U-8：避免拉入 FreeBSD kernel 子集编译爆炸 |
| **仅链被测 `.o` + stubs** | 最小依赖；快速编译（< 5s/单测） |
| **`pkg-config cmocka`** | NFR-U-4 可移植性 |
| **CMocka 版本 guard** | R-U-3 mitigation |
| **`-DFF_UNIT_TEST=1`** | 被测代码可用 `#ifdef FF_UNIT_TEST` 条件暴露 static handler（spec 06 §3.4 方案 B 用） |
| **`make clean` 走 wrapper** | NFR-U-7 工作区合规 |

---

## 6. 编译矩阵（host-only / coverage / valgrind）

### 6.1 host-only 编译矩阵（R-U-2）

| 平台 | gcc 版本 | CMocka 版本 | 期望 | 实测时机 |
|---|---|---|---|---|
| TencentOS 4.4（当前 CVM）| ≥11 | 1.1.7 | ≥98% TC PASS | 阶段二 |
| Ubuntu 22.04 | ≥11 | ≥1.1.5 | ≥98% TC PASS | 阶段二 |
| RHEL 9 | ≥11 | ≥1.1.5 | ≥98% TC PASS | 阶段二 |
| FreeBSD 13/15 | clang ≥14 | ≥1.1.5 | 部分 TC skip（host-only TC 全 PASS）| 阶段三 |

### 6.2 coverage 矩阵（R-U-11）

| flags 组合 | 兼容性 | 备注 |
|---|---|---|
| `-fprofile-arcs -ftest-coverage` + CMocka | ✅ | 阶段三引入 |
| `-fsanitize=address` + CMocka | ✅ | 阶段三作可选 |
| `-fsanitize=memory` + CMocka | ❌ | clang only，不进 |
| `-fsanitize=thread` + CMocka | ⚠ | pthread 测试时可能误报，谨慎用 |

---

## 7. Mock 策略矩阵（11×4，FR-U-5）

### 7.1 总览（依赖统计 + mock 推荐）

| 文件 | rte_* | pthread | sys | printf | 推荐策略 | Fixture 复杂度 |
|---|---:|---:|---:|---:|---|---|
| **ff_ini_parser.c** | 0 | 0 | 0 | 0 | **直接 link real**（无外部依赖） | Trivial |
| **ff_log.c** | 5 | 0 | 0 | 0 | **wrap + will_return**（4 rte 全 wrap） | Easy |
| **ff_host_interface.c** | 6 | 0 | 1 | 0 | wrap rte_malloc/free + sys/mman | Medium |
| **ff_epoll.c** | 0 | 0 | 0 | 0 | link real + 仅 stub ff_kqueue/ff_kevent | Easy |
| **ff_config.c** | 7 | 0 | 0 | 56 | link real + 准备 .ini fixtures + ff_log_stub | Medium |
| **ff_thread.c** | 0 | 2 | 0 | 0 | wrap pthread + ff_malloc/free | Medium |
| **ff_dpdk_pcap.c** | 3 | 0 | 0 | 0 | mock rte_mbuf 数据结构 | Hard |
| **ff_dpdk_kni.c** | 34 | 0 | 0 | 3 | 仅纯函数子集；多数 stub | Hard |
| **ff_init.c** | 0 | 0 | 0 | 0 | stub ff_load_config/ff_dpdk_*/ff_freebsd_init | Hard（stub 多）|
| **ff_dpdk_if.c** | 173 | 0 | 0 | 5 | **仅纯函数子集**（4 候选） | Very Hard |
| **ff_memory.c** | 24 | 0 | 1 | 1 | 默认关闭；P3 暂不投入 | N/A |

**总 cell = 11 × 4 = 44 cell** ✓（FR-U-5 阈值）

### 7.2 P0 文件 mock 详细方案

#### P0 #1 ff_ini_parser.c

- **mock 数 = 0**：仅依赖 stdio (FILE\* / fopen / fgets / ungetc)、ctype、string
- **fixture 设计**：用 `tmpfile()` 或 `fmemopen()` 构造内存 stream；自定义 ini_handler callback 用 cmocka `mock()` 验证调用参数
- **覆盖目标**：ini_parse_stream 状态机所有分支（comment / section / multiline / BOM / inline-comment / 错误恢复）

#### P0 #2 ff_log.c

- **mock 数 = 4**：`__wrap_rte_openlog_stream`, `__wrap_rte_log_set_global_level`, `__wrap_rte_log_set_level`, `__wrap_rte_vlog`
- **fixture 设计**：`ff_global_cfg` 静态实例（来自 `common/ff_log_stub.h`）+ 临时日志路径
- **覆盖目标**：7 公开 API + va_start/va_end 配对

---

## 8. 致命函数处理（R-U-13，**强制规范**）

### 8.1 必须 wrap 的致命函数

| 函数 | 调用方 | wrap 后行为 |
|---|---|---|
| `rte_exit(code, fmt, ...)` | ff_dpdk_if.c × 25+, ff_dpdk_kni.c × 5 | `mock_assert(false, "rte_exit", __FILE__, __LINE__)` |
| `rte_panic(fmt, ...)` | ff_dpdk_kni.c × 4 | `mock_assert(false, "rte_panic", __FILE__, __LINE__)` |
| `exit(int)` | 散见 | `mock_assert(false, "exit", __FILE__, __LINE__)` |
| `abort()` | 散见 | `mock_assert(false, "abort", __FILE__, __LINE__)` |

### 8.2 公共 stub 模板（`common/rte_stub.c`）

```c
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

void __wrap_rte_exit(int code, const char *fmt, ...) {
    (void)code; (void)fmt;
    mock_assert(0, "rte_exit", __FILE__, __LINE__);
    /* unreachable */
}

void __wrap_rte_panic(const char *fmt, ...) {
    (void)fmt;
    mock_assert(0, "rte_panic", __FILE__, __LINE__);
    /* unreachable */
}
```

链接器 flag：`-Wl,--wrap=rte_exit -Wl,--wrap=rte_panic`

### 8.3 验证致命路径的测试（spec 06 §3 用例）

```c
static void test_xxx_invalid_input_calls_rte_exit(void **state) {
    expect_assert_failure(some_func(NULL));   /* 期望内部 rte_exit */
}
```

---

## 9. Fixture 模板（公共 stub）

### 9.1 ff_global_cfg stub（`common/ff_log_stub.h`）

```c
#ifndef FF_LOG_STUB_H
#define FF_LOG_STUB_H

#include <stdio.h>
#include <stdint.h>

/* Minimal shim of ff_global_cfg required by ff_log.c / ff_config.c.
 * Only the .log sub-struct is populated; other fields are zero-init.
 * Declared `extern` here, defined as a static instance in ff_log_stub.c. */
struct ff_log_cfg_stub {
    char        dir[256];
    int         proc_id;
    FILE       *f;
    uint32_t    level;
};
struct ff_config_stub {
    struct ff_log_cfg_stub log;
};
extern struct ff_config_stub ff_global_cfg;

#endif
```

### 9.2 group setup/teardown 通用模板

```c
static int test_xxx_setup(void **state) {
    /* prepare ff_global_cfg.log fields, tmp dir, etc. */
    ff_global_cfg.log.proc_id = 0;
    snprintf(ff_global_cfg.log.dir, sizeof(ff_global_cfg.log.dir), "/tmp/");
    ff_global_cfg.log.level = 7;
    ff_global_cfg.log.f = NULL;
    *state = NULL;
    return 0;
}

static int test_xxx_teardown(void **state) {
    if (ff_global_cfg.log.f) fclose(ff_global_cfg.log.f);
    return 0;
}
```

---

## 10. 性能 budget（NFR-U-5）

| 阶段 | TC 数 | 期望耗时 | 备注 |
|---|---|---|---|
| P0 全套（ff_ini_parser + ff_log）| ~30 | < 3s | 多数为字符串/格式化逻辑 |
| P1 全套（host_interface + epoll + config）| ~50 | < 15s | config 端到端 .ini fixture 略慢 |
| **P0 + P1** | **~80** | **< 30s（NFR-U-5 阈值）** | — |
| P2 follow-up | 待估 | 未估 | 阶段五 |

---

## 11. 与 c-unittest-expert.mdc 方法论的映射

| 方法论原则 | 本 spec 落实位置 |
|---|---|
| 测试命名 `test_<func>_<scenario>` | 04 §4.1 + 06 §1 |
| 边界覆盖（empty / extreme / illegal）| 04 §3 + 06 §5 |
| Setup/teardown 隔离 | 04 §9 |
| 断言粒度细化 | 04 §3 映射表 |
| Mock 边界清晰 | 04 §7 矩阵 + §8 致命函数处理 |
| 1 测试只验 1 行为 | 06 §3 用例编排 |

---

## 12. 阶段二落地 checklist（spec 阶段不执行，仅列）

- [ ] 创建 `tests/unit/` 目录（含 `common/` + `fixtures/`）
- [ ] 落 `tests/unit/Makefile`（基于 §5.1 草案）
- [ ] 落 `common/ff_log_stub.{c,h}` + `common/rte_stub.{c,h}`
- [ ] 写第一个 hello-world test 验证工程链路（仅 `cmocka_unit_test` + `assert_int_equal(2+3, 5)`）
- [ ] CMocka 版本 guard 在 Makefile 中实测生效

---

**文档结束（v0.1，500 行预算内）**
