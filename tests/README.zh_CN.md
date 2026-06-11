# F-Stack `tests/`

F-Stack `lib/` 胶水层的测试套件，包含两套：

| 套件 | 路径 | 是否启动 DPDK EAL | 用途 |
|------|------|-------------------|------|
| **单元（Unit）**        | `tests/unit/`        | 否（rte_* 被 stub/wrap）   | 快速、隔离的逐文件分支/行覆盖率 |
| **集成（Integration）** | `tests/integration/` | 是（`--no-huge --no-pci`） | 需要真实 EAL 的 `ff_dpdk_if.c` 路径 |

合计：**189 个单元测试用例**（分布在 11 个 binary）+ **8 个集成测试用例**。

---

## 1. 前置依赖

- `gcc` + GNU `make`
- `pkg-config` 报告 `cmocka >= 1.1.7`
  - TencentOS 4.x：`dnf install -y libcmocka libcmocka-devel`
  - 验证：`pkg-config --modversion cmocka`
- DPDK 23.11 / 24.11 头文件 + 运行时库（`/usr/local` 下的 `rte_config.h`、`librte_*.so`）
- `lcov` / `genhtml`（生成覆盖率报告）
- `valgrind`（`make check` 内存检查）

覆盖率与集成 binary 链接 DPDK 动态库，运行时需要其运行库路径：

```bash
export LD_LIBRARY_PATH=/usr/local/lib64:$LD_LIBRARY_PATH
```

Makefile 已通过 `RUN_ENV` 为 `make test` / `make check` / `make coverage` 自动注入该路径；
仅当你手动直接运行某个 binary（如 `./test_ff_dpdk_kni`）时才需要自行设置。

---

## 2. 快速开始

```bash
cd /data/workspace/f-stack/tests/unit

make help            # 列出所有 target
make test            # 构建 + 运行全部单元 binary（189 TC）
make check           # 在 valgrind memcheck 下重跑全部（0 leak 门禁）
./run_coverage.sh    # gcov 构建 + 运行 + lcov HTML + G8 阈值门禁
```

整体项目（单元 + 集成 合并）覆盖率：

```bash
cd /data/workspace/f-stack/tests
./run_full_coverage.sh   # 合并 unit + integration 为单一报告
```

---

## 3. 单元套件 —— `make` target

| Target | 作用 |
|--------|------|
| `make all`           | 构建所有测试 binary |
| `make test`          | 构建 + 运行所有套件（sanity + P0 + P1 + P2 + P3）|
| `make test_sanity`   | hello-world cmocka/pkg-config 冒烟测试（2 TC）|
| `make test_p0`       | P0：`ff_ini_parser` + `ff_log` |
| `make test_p1`       | P1：`ff_host_interface` + `ff_epoll` + `ff_config` |
| `make test_p2`       | P2：`ff_thread` + `ff_init` + `ff_dpdk_pcap` + `ff_dpdk_if` |
| `make test_p3`       | P3：`ff_dpdk_kni` |
| `make check`         | 在 `valgrind --tool=memcheck` 下运行每个 binary（definite leak 即失败）|
| `make coverage`      | gcov 构建 + 运行 + 生成 `coverage_report/index.html` |
| `make clean`         | 清理构建产物（经 `rm_tmp_file.sh` 封装）|
| `make coverage_clean`| 清理 `.gcda/.gcno` + `coverage_report/` |

也可单独构建/运行某个 binary：

```bash
make test_ff_config
LD_LIBRARY_PATH=/usr/local/lib64:$LD_LIBRARY_PATH ./test_ff_config
```

### 测试 binary → lib 文件 映射

| Binary | 分组 | 被测 lib 文件 | TC | 说明 |
|--------|------|---------------|----|------|
| `test_hello`             | sanity | — | 2 | 工具链冒烟测试 |
| `test_ff_ini_parser`     | P0 | `ff_ini_parser.c` | 25 | inih 风格解析器 |
| `test_ff_log`            | P0 | `ff_log.c` | 13 | 4 个 `rte_log` API wrap |
| `test_ff_host_interface` | P1 | `ff_host_interface.c` | 22 | 链接 libcrypto（RAND_bytes）|
| `test_ff_epoll`          | P1 | `ff_epoll.c` | 21 | kqueue/kevent 合成 stub |
| `test_ff_config`         | P1 | `ff_config.c` | 50 | 经 `ff_load_config` 端到端；OOM 用 `--wrap=calloc` |
| `test_ff_thread`         | P2 | `ff_thread.c` | 4 | 链接真实 pthread |
| `test_ff_init`           | P2 | `ff_init.c` | 6 | `--wrap=ff_malloc` |
| `test_ff_dpdk_pcap`      | P2 | `ff_dpdk_pcap.c` | 9 | 栈上 mbuf + pcap 轮转 |
| `test_ff_dpdk_if`        | P2 | `ff_dpdk_if.c` | 19 | 仅单元可 mock 的子集 |
| `test_ff_dpdk_kni`       | P3 | `ff_dpdk_kni.c` | 18 | 启动 EAL `--no-huge`；以 `-DFF_KNI` 编译 |

---

## 4. 覆盖率脚本

### 4.1 `unit/run_coverage.sh` —— 单元覆盖率 + G8 门禁

```bash
./run_coverage.sh              # 全量：clean + gcov 构建 + 运行 + 报告 + G8 汇总
./run_coverage.sh --quick      # 复用已有 .gcda（跳过重新构建）
./run_coverage.sh --file ff_config.c   # 查看单文件逐行 gcov 明细
./run_coverage.sh --serve      # 额外在 :8080 起 HTTP 服务查看 HTML 报告
./run_coverage.sh --clean      # 清除所有覆盖率产物后退出
./run_coverage.sh -h           # 帮助
```

退出码：`0` 成功且所有 G8 阈值达标 · `1` 构建/测试失败或 G8 违规 · `2` 参数错误。

HTML 报告：`unit/coverage_report/index.html`。

### 4.2 `unit/coverage_threshold.sh` —— “G8” 逐文件门禁

由 `run_coverage.sh` 末尾自动调用。它解析 `coverage.info`，对每个文件强制
最低 **行（line）** 与 **分支（branch）** 百分比。阈值以 `tline["<file>"]` /
`tbr["<file>"]` 形式维护，每轮覆盖率提升后向上 ratchet（保持在 `实测值 − 约5pp`
作为回归防护）。

### 4.3 `run_full_coverage.sh` —— 单元 + 集成 合并

```bash
cd tests
./run_full_coverage.sh         # 构建 + 运行两套件，合并，出报告
./run_full_coverage.sh --quick # 复用已有 .info trace
./run_full_coverage.sh --clean # 清除所有覆盖率产物
```

合并 HTML 报告：`tests/full_coverage_report/index.html`。

---

## 5. 集成套件 —— `tests/integration/`

与单元套件不同，本套件会启动**真实 DPDK EAL**（`--no-huge`、`--no-pci`），
以覆盖依赖真实 mempool / ring / ethdev 的 `ff_dpdk_if.c` 路径。若 EAL 初始化失败
（如权限不足），相关用例会 `skip()` 而非失败。

```bash
cd tests/integration
make help
make test            # 运行集成测试（8 TC）
make check           # 在 valgrind 下运行
make coverage        # gcov 构建 + 报告 -> coverage_report/index.html
make clean
```

---

## 6. 当前覆盖率快照（单元 + 集成 合并）

| 文件 | line | branch | 备注 |
|------|------|--------|------|
| `ff_log.c`            | 100%  | 100%  | 已封顶 |
| `ff_thread.c`         | 100%  | 100%  | 已封顶 |
| `ff_init.c`           | 100%  | 100%  | 已封顶 |
| `ff_dpdk_pcap.c`      | 100%  | 100%  | L118 死腿 `LCOV_EXCL_BR_LINE` |
| `ff_epoll.c`          | 100%  | 100%  | |
| `ff_host_interface.c` | 100%  | 98.1% | 2 个 clock-assert 腿需 `--wrap=__assert_fail` |
| `ff_ini_parser.c`     | 98.7% | 91.2% | 6 个 `&&!error` 腿因 `INI_STOP_ON_FIRST_ERROR` 死 |
| `ff_config.c`         | 89.9% | 85.4% | 剩余为 OOM/数据流单腿 |
| `ff_dpdk_kni.c`       | 59.9% | 51.6% | tx/rx/alloc 需集成（`rte_eth_*_burst` 为 `static inline`，不可 wrap）|
| `ff_dpdk_if.c`        | 30.8% | 22.6% | 多数仅集成可达 |
| **项目（合并）**       | 62.9% | 63.7% | |

> 这些数字由 `run_coverage.sh` / `run_full_coverage.sh` 产出，重新运行即可刷新。
> 权威来源始终是新生成的 `coverage.info`，而非本表。

---

## 7. 为已有 lib 文件新增测试

1. 在 `unit/Makefile` 中增加 per-target 规则，列出要链接的 `lib_objs/*.o` + stub，
   以及该文件所需的 `-Wl,--wrap=<sym>` 标志（参考 `WRAP_FF_LOG`、`WRAP_FF_DPDKIF`、
   `test_ff_config` 的 `--wrap=calloc`，以及 `ff_dpdk_kni.o: KNI_EXTRA_CFLAGS := -DFF_KNI`
   的 per-object 覆盖写法）。
2. 把 binary 名加入相应的 `P{0,1,2,3}_TESTS` 分组。
3. 按 cmocka 模板创建 `test_<file>.c`（`group_setup` / `test_setup` /
   `cmocka_unit_test_setup_teardown`）。
4. 命名规范：`test_<function>_<scenario>_<expected>`。
5. `make test_<file>` 构建并运行，再用 `./run_coverage.sh --file <file>.c`
   确认目标分支已覆盖。

### Mock / wrap 基础设施

- `common/rte_stub.c` —— `__wrap_rte_exit` / `__wrap_rte_panic` 重定向到
  cmocka `mock_assert`，使回归绝不会以 `SIGABRT` 终止测试框架。
- `common/ff_log_stub.{c,h}` —— 为不链接 `lib/ff_log.c` 的 binary 提供
  `struct ff_config ff_global_cfg` 及空实现的 `ff_log`。
- OOM 测试：`--wrap=calloc` 配合 armed 计数器（`g_calloc_fail_after`），未武装时
  透传到 `__real_calloc`，让某个 TC 精确地让第 N 次分配失败，且不干扰 cmocka 自身分配。
- 内联 DPDK 辅助函数（`rte_eth_tx_burst`、`rte_eth_rx_burst`、
  `rte_ring_dequeue_burst`）为 `static inline`，**无法**被 `--wrap`；
  测试这些路径需要带真实 PMD 的集成套件。

---

## 8. 遵循的工作区规约

- 所有临时文件删除均经 `/data/workspace/rm_tmp_file.sh`
  （Makefile `clean` target 使用它；无任何直接 `rm`）。
- 全树无任何直接 `rm` / `kill` / `pkill` / `killall` / `chmod` 调用。
- 测试进程绝不调用真实 `rte_exit` / `rte_panic`（经 `__wrap_*` → `mock_assert` 拦截）。

---

## 9. 设计参考

- 规格文档：`docs/unit_test_spec/zh_cn/`（`04-cmocka-framework-and-impl.md`、
  `06-test-cases-and-acceptance.md`、Stage-7 `7x-*.md`、Stage-8 `8x-*.md`）
- 方法论：`c-unittest-expert` 技能（基于 Unity，已映射到 CMocka API）
- 各阶段评审：`docs/unit_test_spec/zh_cn/{99-*,79-stage7-review,89-stage8-review}.md`
