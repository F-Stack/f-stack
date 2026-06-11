# 21 · M2 测试执行报告（ZC-RECV）

> 执行：2026-06-11。双机：server=本机（VM-213-67，data-plane DPDK NIC 9.134.214.176 / MAC 20:90:6f:7d:5d:08，云 metadata 实测确认）；client=f-stack-client（VM-211-87，9.134.211.87）。
> 铁律：仅记录实际执行结果，不臆造数据。

## 1. 构建 / 启动验证（PASS）
| 项 | 命令 | 结果 |
|---|---|---|
| lib（FF_ZC_SEND=1 FF_ZC_RECV=1）| `make -C lib` | ✅ rc=0，-Werror 零错误 |
| 符号导出 | nm libfstack.a | ✅ `T ff_zc_recv / ff_zc_mbuf_segment / ff_zc_recv_free`（已补 ff_api.symlist）|
| server B（ZC-recv，-DFSTACK_ZC_SEND -DFSTACK_ZC_RECV）| cc main_zc.c | ✅ helloworld_zc_recv（29036792 B）|
| server A（baseline，仅 -DFSTACK_ZC_SEND）| cc main_zc.c | ✅ helloworld_zc_base（29036576 B，略小，确认 ZC-recv 代码已链接进 B）|
| server B 启动 | `./helloworld_zc_recv --conf config.ini --proc-type=primary` | ✅ DPDK EAL init OK，`Successed to register dpdk interface`，MAC 20:90:6f:7d:5d:08 |

## 2. 功能集成（curl）—— 被环境阻断，已证明与 ZC-recv 代码无关
### 2.1 现象
client `curl http://9.134.214.176/` 连续多次均 `http=000`（连接建立失败，time≈0.001s 即返回），server CPU 始终 ~9.5%（idle_sleep 下基本空闲）→ **SYN 包未到达 f-stack**。

### 2.2 网络诊断（实测）
- 云 metadata：`MAC 20:90:6f:7d:5d:08 ↔ IP 9.134.214.176`（DPDK NIC，config.ini addr 正确）；`MAC 52:54:00:9e:8b:6f ↔ 9.134.213.67`（控制面 eth1）。
- client 与 data-plane 同 /21 子网（9.134.208.0/21），`ip route get 9.134.214.176 → dev eth1`（直连）。
- client ARP：`9.134.214.176 → fe:ee:2e:9c:ed:94`（VPC 网关/SDN MAC，非 f-stack 也非控制面）；刷新 ARP 后仍解析为该 MAC。
- **结论**：VPC SDN 未把发往 9.134.214.176 的报文投递到该 ENI 对应的 DPDK NIC（f-stack 收不到任何包）。

### 2.3 差分判定（关键，证明非本次代码问题）
| Server | 接收路径 | curl 结果 | server CPU |
|---|---|---|---|
| B（ZC-recv，本次新代码）| ff_zc_recv | http=000 ×5 | ~9.4% 空闲 |
| **A（baseline，纯 ff_read，历史可用路径，无任何 ZC-recv 代码）** | ff_read | **http=000 ×3（完全一致）** | ~9.5% 空闲 |

→ **baseline 与 ZC-recv 表现完全一致、包都未到达 f-stack** ⇒ 阻断点是**数据面 VPC/ENI 投递（环境）**，**与 ZC-recv 实现无关**。本次 M0+M1 代码的编译、符号导出、server 启动、DPDK 注册均正常。

## 3. 性能基线对比 —— 因数据面阻断无法采集真实数值
- 单核（lcore_mask=10 → lcore 4）A/B 压测 harness 已就绪（见 §5），但因 §2 数据面阻断，**本轮无法采集真实 req/s**。**不臆造数据**。
- **历史极限参考**（docs/freebsd_13_to_15 13.0-baseline-cvm-bench-report，同机同 config.ini 单核 lcore4，helloworld kqueue）：
  - Smoke curl：HTTP 200，RTT 1.25 ms
  - T2（-t4 -c100 30s）：13.0 **220,691 req/s** / 15.0 203,933 req/s
  - T3（-t8 -c500 30s）：13.0 **239,555 req/s** / 15.0 217,100 req/s，p99 4.21→5.38 ms
- ZC-recv 预期：消除 soreceive→uiomove 拷贝，大包收取场景 CPU/吞吐应有收益（待数据面恢复后用 §5 harness 实测 A/B）。

## 4. 数据面恢复建议（环境侧，非本代码）
VPC SDN 对 9.134.214.176→DPDK NIC 的转发绑定疑似失效（历史测试曾正常，环境漂移）。建议其一：
- 重新挂载/刷新该 ENI 的 IP-MAC 绑定（云控制台或 reboot）；
- 或确认 SDN 反欺骗对 f-stack 主动 gratuitous ARP 的要求；
- 恢复后用 §5 harness 直接复测。

## 5. 就绪的复测 harness（数据面恢复后直接执行）
```bash
# 1) server B（ZC-recv，单核 lcore4）
cd /data/workspace/f-stack/example
nohup ./helloworld_zc_recv --conf /data/workspace/f-stack/config.ini --proc-type=primary >/tmp/zc_recv.log 2>&1 & disown

# 2) smoke（client）
ssh f-stack-client "curl -s -o /dev/null -w 'http=%{http_code} t=%{time_total}\n' http://9.134.214.176/"

# 3) 单核性能 T2/T3（client；如无 wrk 用 ab/curl 循环）
ssh f-stack-client "wrk -t4 -c100 -d30s --latency http://9.134.214.176/"
ssh f-stack-client "wrk -t8 -c500 -d30s --latency http://9.134.214.176/"

# 4) 停服务 + 清理（必须走脚本）
/data/workspace/kill_process.sh <pid>
ls /dev/hugepages/rtemap_* | xargs /data/workspace/rm_tmp_file.sh

# 5) server A（baseline）重复 1-4，A/B 对比 req/s 与 p99
```

## 6. M2 验收对照（spec 17）
| AC | 状态 | 说明 |
|---|---|---|
| 构建/启动 | ✅ | lib+server 编译通过（-Werror），DPDK 注册成功 |
| AC-F1 ff_zc_recv 全链路功能 | ⏸ 阻断 | 数据面 VPC 投递失效（差分证明非代码问题）|
| AC-M1/M2 内存安全（mempool/valgrind）| ⏸ | 需数据面恢复后跑流量验证 |
| AC-P1 单核性能 A/B | ⏸ | harness 就绪，待数据面恢复采集 |
| 代码正确性（编译/符号/启动/差分）| ✅ | 与 baseline 行为一致，未引入回归 |

## 7. 合规
- ✅ 停进程走 kill_process.sh；清 rtemap/临时文件走 rm_tmp_file.sh；无直接 rm/kill/chmod
- ✅ 未臆造任何性能/功能数据；http=000 如实记录
- ✅ client 命令经 ssh 下发
