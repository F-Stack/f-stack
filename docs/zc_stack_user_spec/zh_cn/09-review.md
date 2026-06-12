# 09 · 文档审核门禁记录

> gatekeeper（独立抽检）。审核 4 维：①引用真实性 ②行号/符号吻合 ③结论有依据 ④无臆测。

## 关键引用抽检结果（实测 grep/sed 核对）
| 检查项 | 文档断言 | 实测核对 | 结果 |
|---|---|---|---|
| G1 | ff_zc_mbuf_read 空 stub @ ff_veth.c:359 | `ff_zc_mbuf_read(...){ // DOTO...; return 0; }` 确在 358-363 | ✅ |
| G2 | ff_zc_send 设 uio_offset=MAGIC | `auio.uio_offset = FSTACK_ZC_MAGIC` @ ff_syscall_wrapper.c:1216 | ✅ |
| G3 | FSTACK_ZC_MAGIC 定义 | `#define FSTACK_ZC_MAGIC ((off_t)0xF8AC2C00F8AC2C00LL)` @ mbuf.h:1868 | ✅ |
| G4 | RX m_extadd EXT_DISPOSABLE | `m_extadd(m,data,len,ff_mbuf_ext_free,pkt,NULL,0,EXT_DISPOSABLE)` @ ff_veth.c:374（多段 399）| ✅ |
| G5 | kern_recvit soreceive mp0 写死 NULL | `soreceive(so, &fromsa, &auio, NULL,` @ uipc_syscalls.c:948 | ✅ |
| G6 | soreceive mp!=NULL 零拷贝直交分支 | `sbfree(...); if(mp!=NULL){ *mp=m; mp=&m->m_next; sb_mb=m=m->m_next; }` @ uipc_socket.c:~3060-3066 | ✅ |
| G7 | mp==NULL uiomove 拷贝点 | `if(mp==NULL){ ... uiomove(mtod(m,char*)+moff,len,uio) }` @ uipc_socket.c:~3022-3031 | ✅ |

抽检命中率 **7/7 = 100%**。所有行号在容差内吻合（mp 分支实际 sbfree@3060 / *mp=m@3063，文档标注 3061-3066，吻合）。

## 4 维裁决
| 文档 | 引用真实性 | 行号吻合 | 结论有依据 | 无臆测 | 裁决 |
|---|---|---|---|---|---|
| 00-plan | N/A | N/A | ✓ | ✓ | PASS |
| 01-zcsend-baseline | ✓ | ✓ | ✓ | ✓ | PASS |
| 02-recv-path-analysis | ✓ | ✓ | ✓ | ✓ | PASS |
| 03-extmbuf-lifecycle | ✓ | ✓ | ✓ | ✓（§4/§5 设计级项已标"待设计验证"）| PASS |
| 04-external-research | ✓（外网+代码交叉）| ✓ | ✓ | ✓ | PASS |
| 05-design-and-feasibility | ✓ | ✓ | ✓ | ✓（工作量/里程碑标"实现期"）| PASS |

## 验收门禁 G-ZCR-1..7
| Gate | 结果 |
|---|---|
| G-ZCR-1 引用真实性 100% 命中 | ✅ 7/7 |
| G-ZCR-2 ≥2 内核机制方案对比+推荐 | ✅ 05 §1（A 复用 mp0 / B 仿 magic，推荐 A）|
| G-ZCR-3 生命周期闭环论证 | ✅ 05 §3 + 03 §2/§4/§6 |
| G-ZCR-4 边界矩阵覆盖 | ✅ 05 §4（整/split/PEEK/WAITALL/DONTWAIT/OOB/SCM/TLS/UDP）|
| G-ZCR-5 明确可行性结论+工作量+里程碑 | ✅ 05 §0/§5/§6（可行，8-15 人天）|
| G-ZCR-6 外网与代码不一致以代码为准 | ✅ 04 §5 全一致，无冲突 |
| G-ZCR-7 仅中文+无臆测 | ✅ 全中文，设计级项均标注 |

## 打回/修正记录
- 无打回。一处文档措辞修正：01 §5 明确"ZC-send/read 方向相反，不宜强行对称复刻 magic"，与 02/05 选型一致。

## 最终裁决：**全部 PASS，可行性调研通过。**
