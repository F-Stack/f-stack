# Phase-2 M9 Spec — FF_USE_PAGE_ARRAY + FF_ZC_SEND combo (P1c)

> 状态：DRAFT → ready
> 上游基础：M8 commit `add33a04a`
> 复杂度：S（仅 1 行 Makefile + 复用 M7/M8 验收路径）

---

## 1. 目标 / 范围

### in-scope

- `lib/Makefile` 同时启用 `FF_USE_PAGE_ARRAY=1` + `FF_ZC_SEND=1`
- 复用 M7 + M8 已就位的代码（无新代码改动）
- G1 编译 + G2 冒烟 + G3 端到端 + G4 性能 observation 全套验证
- 文档 anchor + execution log

### out-of-scope

- 任何源码改动（已在 M7/M8 完成）
- 性能 NFR-2 标定（OQ-2 默认许可；完整基线推迟到独立 phase）

---

## 2. Acceptance Criteria

| ID | 验收 |
|---|---|
| AC-M9-1 | `lib/Makefile` 同时取消注释 `FF_USE_PAGE_ARRAY=1` + `FF_ZC_SEND=1` |
| AC-M9-2 | `lib/ make clean && make`：exit=0 / 0 errors / warnings ≤ 60 |
| AC-M9-3 | `example/ make`：3 binaries 全产出 |
| AC-M9-4 | helloworld_zc primary 起栈 ≥ 12s ALIVE，log 含 `ff_mmap_init mmap 65536 pages, 256 MB.`（PA）+ ipfw2 init 行（ZC 路径独立无冲突） |
| AC-M9-5 | ssh f-stack-client 单 curl HTTP 200 + 真实 HTML body |
| AC-M9-6 | 100x 短连：100/100 PASS |
| AC-M9-7 | 文档 anchor 同 M6/M7/M8 模式 |

---

## 3. 风险

| ID | 风险 | 缓解 |
|---|---|---|
| R-M9-1 | PA mmap 后 ZC fast-path 取 mbuf 来自 m_getm2，与 PA 池可能交叉 | M7 PA 仅影响 mbuf 数据 cluster 来源（mmap vs malloc），与 ZC fast-path mbuf chain 解释正交；理论无冲突 |
| R-M9-2 | 256MB mmap 占用 + ZC magic check 偶有路径漏点 | 复用 M7 baseline + 100x 压测验证 |

---

## 4. 验收命令

```sh
# G1
cd /data/workspace/f-stack/lib && make clean && make
cd /data/workspace/f-stack/example && /data/workspace/rm_tmp_file.sh ./helloworld ./helloworld_zc ./helloworld_epoll && make

# G2/G3
/data/workspace/rm_tmp_file.sh /var/run/dpdk/rte/{config,fbarray_*,hugepage_info}
sudo ./helloworld_zc -c ../config.ini --proc-type=primary --proc-id=0 &
sleep 12 && [ -d /proc/$PID ] && echo ALIVE
ssh f-stack-client 'curl -sS -o /dev/null -w "%{http_code}\n" http://9.134.214.176/'
ssh f-stack-client 'OK=0; for i in $(seq 1 100); do CODE=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 http://9.134.214.176/); [ "$CODE" = 200 ] && OK=$((OK+1)); done; echo $OK/100'
/data/workspace/kill_process.sh $PID
```

---

> 下一步：Phase C — 1 行 Makefile diff + 重编 + Gate run。
