# eBPF 诊断实验（#27）

## 前提与边界

- eBPF 是**实验特性**,不替代现有 tracefs 路径;默认构建**不引入** eBPF 依赖。
- 能力不满足时明确报 `unsupported`（MCP `ebpf_doctor` 工具），绝不伪造数据。
- 权限模型与 probe-helper 一致：特权操作在独立 root 服务完成。

## 能力矩阵（`system_monitor ebpf_doctor` / MCP `ebpf_doctor`）

| 检查项 | 前提 | 不满足时 |
| --- | --- | --- |
| kernel_version | ≥ 5.8 | 报告实际版本并停止 |
| btf | /sys/kernel/btf/vmlinux | CO-RE 不可用，报 unsupported |
| bpf_syscall | bpf(2) 可达（seccomp 放行） | 报告被禁 |
| perf_events | /sys/kernel/perf_event_paranoid 存在 | 报告缺失 |
| tracefs | 已挂载 | 实验与回退路径均不可用 |

## 资源上限（可配置）

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| SM_EBPF_MAX_ENTRIES | 16384 | 每场景 map 条目上限 |
| SM_EBPF_MAX_SECS | 300 | 单会话最长秒数 |
| SM_EBPF_SAMPLE_RATE | 1 | 每 N 次事件采样 1 条 |

## 三个首批场景的可复现实验

当前实现走 **tracefs 路径**（probe-helper 协议已就绪，输出结构化事件可作诊断
会话的 Evidence）；eBPF 版本（aya，feature `ebpf`）为后续演进,输出同构。

### 1. 调度延迟（sched_delay）

```bash
# tracefs 路径：sched_switch tracepoint 采样
sudo scripts/install-probe-helper.sh
# 挂载 tracepoint:sched_switch 观测 prev_comm 的运行队列等待
# （MCP: probe_attach kind=syscall/kprobe 亦可;此处为事件计数验证）
cat /sys/kernel/tracing/events/sched/sched_switch/enable  # 确认可写
# 采集 60s,对比 psi.cpu.some avg10(应同向)
```

### 2. 块 I/O 延迟（block_io_latency）

```bash
# block_rq_issue / block_rq_complete kprobe 配对
grep block_rq /sys/kernel/tracing/available_events
# issue 与 complete 时间差 = 延迟;tracefs 路径用 timestamp 字段做对账
```

### 3. TCP 重传（tcp_retrans）

```bash
# tcp_retransmit_skb tracepoint 计数
nstat -az TcpRetransSegs   # /proc/net/snmp 交叉验证
# 实验会话内两次读数差 = 会话期重传数;与 tracepoint 计数对账
```

## eBPF 版本演进约定

- feature `ebpf`（默认关）；独立子命令加载,不进常驻进程。
- map/直方图上限沿用 ResourceLimits;加载失败降级 tracefs 并在输出中标注 `fallback: tracefs`。
