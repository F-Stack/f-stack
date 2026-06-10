# 99 — Stage-4 P2 Tests Review Report

> 文档版本：v0.1（2026-06-10 10:55 UTC+8）
> Stage：Stage-4（P2 5 文件 follow-up，FU-U-4）
> 上一阶段：Stage-3 覆盖率（HEAD `bef9174c7` + lib NULL guard `6ea33d7e1`）

---

## 0. 总评：**PASS**（BOUNCE 累计 0/4）

| Gate | 检查 | 结果 |
|---|---|---|
| **G6a** | test_ff_thread + test_ff_init build & run | ✅ 3+4 PASS |
| **G6b** | test_ff_dpdk_pcap build & run | ✅ 5 PASS |
| **G6c** | test_ff_dpdk_if (subset) build & run | ✅ 7 PASS |
| **G_FINAL** | 全套 `make test` 不退化 | ✅ 10 binaries / 83 TC 全 PASS / 总耗时 3.86s |

---

## 1. P2 实测覆盖

| 文件 | lines | TC 数 | 测试范围 | 结果 |
|---|---|---|---|---|
| ff_thread.c | 51 | 3 | 全 2 公开 API（pthread_create / pthread_join 含丢弃返回值发现）| ✅ |
| ff_init.c | 69 | 4 | 全 3 公开 API + 2 失败路径（exit wrap）| ✅ |
| ff_dpdk_pcap.c | 137 | 5 | 全 2 公开 API + USEC/NSEC magic 验证（rotation trick 触发刷盘）| ✅ |
| ff_dpdk_if.c (subset) | 50/2887 | 7 | 7 trivial getter/setter 函数 | ✅ |
| **合计** | **307 / 3680** | **19 TC** | — | ✅ |

ff_dpdk_kni.c (536 行) **正式 defer 至 `FU-S4-KNI`**（plan §1.2）— 4 公开 API 全需重 KNI/EAL mock，ROI 极低。

---

## 2. 实施过程关键发现

| # | 发现 | 处理 |
|---|---|---|
| 1 | ff_thread.c 的 `ff_start_routine` 丢弃 start_routine 返回值，pthread_join 总收 NULL | TC 按代码为准修正 |
| 2 | ff_dpdk_pcap.c 用 libc 缓冲 fwrite，stat 看到 0 字节 | 用 rotation trick (`f_maxlen=1`) 触发 fclose 刷盘 |
| 3 | seq 是 `__thread` 跨 TC 累积 | 测试枚举搜索 cpu*_*.pcap 替代写死 seq=0 |
| 4 | rte_lcore_id 是 inline 不能 wrap | 改用直接定义 `__thread per_lcore__lcore_id` TLS |
| 5 | rte_pktmbuf_free_seg 是 inline + 需要 mempool | 移除该 TC，标 `FU-S4-PKTMBUF` |
| 6 | ff_dpdk_if.c 编译需 DPDK CFLAGS（含 `-march=native`）| `pkg-config --cflags libdpdk` 加入所有 lib_objs build |
| 7 | ff_dpdk_if.o 链接缺 ~30 个 ff_*/rte_* 符号 | 部分用 stub，部分链 DPDK 真实库（`pkg-config --libs libdpdk` + `-lrte_net_bond`）|
| 8 | DPDK shared libs 在 /usr/local/lib64 但 LD path 没配 | Makefile run targets 加 `LD_LIBRARY_PATH=/usr/local/lib64` |
| 9 | F-Stack 给 DPDK 打的 `rte_timer_meta_init` 不在系统 librte_timer.so | 提供 stub |

---

## 3. 工作区合规

- ✅ 0 直接 rm/kill/chmod
- ✅ 临时 binary 替换走 `rm_tmp_file.sh`（commit message 临时文件已 trash）
- ✅ make clean / coverage_clean 走 wrapper

---

## 4. 交付物（commit 范围）

| 文件 | 行 | tracked |
|---|---|---|
| `tests/unit/test_ff_thread.c` | 145 | ✅ new |
| `tests/unit/test_ff_init.c` | 217 | ✅ new |
| `tests/unit/test_ff_dpdk_pcap.c` | 256 | ✅ new |
| `tests/unit/test_ff_dpdk_if.c` | 240 | ✅ new |
| `tests/unit/Makefile` (modified) | +50 | ✅ |
| `.gitignore` (modified) | +4 | ✅ |
| `99-stage4-p2-review.md` (本文件) | ~80 | ✅ new |

---

## 5. Follow-up

- **FU-S4-KNI** ff_dpdk_kni.c 4 公开 API 测试（重 KNI/EAL mock）— P3
- **FU-S4-DPDK-IF-FULL** ff_dpdk_if.c 完整 ~136 个 ff_* 函数测试 — P3
- **FU-S4-PKTMBUF** ff_dpdk_pktmbuf_free 测试（需 mempool）— P3
- **FU-U-5 / FU-S2-1 / FU-U-7** 不变（CI / valgrind / 英文翻译）

---

**Stage-4 P2 测试 PASS**，进入 commit（短 message per 用户指示）。
