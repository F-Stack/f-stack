# f-stack/freebsd/netgraph/ LEGACY-13 文件清单

> 本文件由 M1 实施 T-misc-01 阶段建立（2026-05-28），列出 `f-stack/freebsd/netgraph/` 子树中保留 13.0 字节版本的文件（在 FreeBSD 15.0 上游已被删除）。
> 文件级 LEGACY pattern，与 `freebsd-src-releng-15.0/f-stack-lib/tools/compat/include/netgraph/LEGACY.md`（99 §12.12）同质。

## 1. 背景

FreeBSD 15.0 上游 `sys/netgraph/` 子树相对 13.0 删除了若干模块；F-Stack 因兼容/历史依赖原因继续保留这些 13.0 字节副本。

## 2. LEGACY-13 文件列表（保留 13.0 字节，不视为 15.0 上游基线）

| 路径（相对本目录） | 类型 | 13.0 来源 | 15.0 上游状态 | 删除原因 / 依据 |
|---|---|---|---|---|
| `atm/` | 整子目录 | `freebsd-src-releng-13.0/sys/netgraph/atm/`（14 文件） | 已删除 | ATM 模块整体退役 |
| `bluetooth/drivers/h4/` | 整子目录 | `freebsd-src-releng-13.0/sys/netgraph/bluetooth/drivers/h4/`（4 文件） | 已删除 | h4 蓝牙驱动退役 |
| `bluetooth/include/ng_h4.h` | 单文件 | `freebsd-src-releng-13.0/sys/netgraph/bluetooth/include/ng_h4.h` | 已删除 | 配套 h4 驱动 |
| `ng_atmllc.c` | 单文件 | `freebsd-src-releng-13.0/sys/netgraph/ng_atmllc.c` | 已删除 | ATM LLC 配套 |
| `ng_atmllc.h` | 单文件 | `freebsd-src-releng-13.0/sys/netgraph/ng_atmllc.h` | 已删除 | ATM LLC 配套 |
| `ng_sppp.c` | 单文件 | `freebsd-src-releng-13.0/sys/netgraph/ng_sppp.c` | 已删除 | `UPDATING:981`：The synchronous PPP kernel driver sppp(4) has been removed. |
| `ng_sppp.h` | 单文件 | `freebsd-src-releng-13.0/sys/netgraph/ng_sppp.h` | 已删除 | 同上 |

合计：5 个单文件 + atm/ 14 文件 + bluetooth/drivers/h4/ 4 文件 = 23 个 LEGACY-13 文件。

## 3. 与 99 §12.12 的关系

99 §12.12 已建立 `f-stack-lib/tools/compat/include/netgraph/LEGACY.md`（针对 ng_atmllc.h / ng_sppp.h 头文件），本 LEGACY.md 是其在 `f-stack/freebsd/netgraph/` 子树的扩展（覆盖 .c 源文件 + atm/ + bluetooth/drivers/h4/ 整子目录）。

## 4. 复核命令

```bash
# 验证 LEGACY 文件存在
ls /data/workspace/f-stack/freebsd/netgraph/atm/ | wc -l       # 应 = 14
ls /data/workspace/f-stack/freebsd/netgraph/bluetooth/drivers/h4/ | wc -l  # 应 = 4
ls /data/workspace/f-stack/freebsd/netgraph/bluetooth/include/ng_h4.h
ls /data/workspace/f-stack/freebsd/netgraph/ng_atmllc.[ch] /data/workspace/f-stack/freebsd/netgraph/ng_sppp.[ch]

# 验证 LEGACY 字节与 13.0 一致
diff -rq /data/workspace/freebsd-src-releng-13.0/sys/netgraph/atm /data/workspace/f-stack/freebsd/netgraph/atm
diff -rq /data/workspace/freebsd-src-releng-13.0/sys/netgraph/bluetooth/drivers/h4 /data/workspace/f-stack/freebsd/netgraph/bluetooth/drivers/h4
cmp /data/workspace/freebsd-src-releng-13.0/sys/netgraph/bluetooth/include/ng_h4.h /data/workspace/f-stack/freebsd/netgraph/bluetooth/include/ng_h4.h
for f in ng_atmllc.c ng_atmllc.h ng_sppp.c ng_sppp.h; do
  cmp /data/workspace/freebsd-src-releng-13.0/sys/netgraph/$f /data/workspace/f-stack/freebsd/netgraph/$f
done
```

## 5. 关联

- `f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/M1-research-brief.md` §7.2 / §9-3
- `f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/M1-execution-log.md` §3 任务 T-misc-01
- `f-stack/docs/freebsd_13_to_15_upgrade_spec/zh_cn/99-review-report.md` §12.12（同质 LEGACY pattern）
