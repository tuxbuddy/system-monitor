# AGENTS.md

给在本仓库工作的编码 Agent 的项目约定。优先相信本文件与 CI 配置，不要凭印象改架构。

## 项目定位

Linux 桌面资源监控与调度工具：Rust workspace、egui 原生 GUI、TUI、MCP stdio 服务、SSH 远端采集、cgroup 限额与 ftrace 探针。目标平台包含 Raspberry Pi / ARM64 桌面。

## 快速验证（提交前至少跑前四项）

```bash
cargo build --release
cargo test --workspace
cargo test --workspace --no-default-features        # 纯 TUI，CI 矩阵也跑这个
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --no-default-features --all-targets -- -D warnings

cargo deny check licenses bans                      # 改依赖后
cargo audit                                         # 改依赖后
```

- GUI 构建需要系统库：`libxkbcommon-dev libwayland-dev libx11-dev libxcursor-dev libxrandr-dev libxi-dev libgl1-mesa-dev libegl1-mesa-dev pkg-config`（CI 用这组）。
- 仓库没有固定 rustfmt 配置/版本；若本机无 `cargo fmt`，按现有风格手工对齐，不要引入大规模格式 diff。
- CI 在 Ubuntu 24.04 跑 clippy + 测试，另在 Ubuntu 22.04 / Debian 12 / Fedora 41 / Arch 容器里跑纯 TUI 测试；跨发行版差异优先用能力探测而不是硬编码路径。
- 性能基准：`cargo bench --no-default-features -p system-monitor --bench parse`（CI 仅存档结果，不设阈值门禁）。

## 目录与依赖方向

```
apps/monitor            system-monitor 二进制入口（TUI/GUI/MCP/mcp-approve/ebpf-doctor）
  └─ crates/monitor-app     应用服务层 + 前端（MCP、TUI、GUI）
       ├─ crates/monitor-remote   SSH 采集与远端动作
       └─ crates/monitor-linux    本地 /proc、cgroup、探针、平台能力
            └─ crates/monitor-core  纯逻辑：策略、PSI 解析、SSH 目标校验、文件原子写
crates/monitor-agent     受管 Agent PoC（独立；单机主程序不得依赖它）
```

- 新增跨层能力先判断属于哪层；纯函数解析放 `monitor-core` 或对应 crate 的纯模块，便于单测。
- 不要为单个功能新增第三方依赖；现有依赖已受 `deny.toml` 约束。

## 必须保持的不变量

1. **写操作唯一入口**：任何改变系统状态的 MCP/GUI/TUI 动作都走 `monitor_app::service::CommandDispatcher`（策略 + 审计 + 统一错误）。不要在 UI 或 MCP 层直接调用 `kill`/cgroup 写入。
2. **MCP 工具面三处同步**：新增/删除工具时同时更新
   - `crates/monitor-app/src/mcp.rs::tools()`
   - `crates/monitor-core/src/mcppolicy.rs::catalog()`
   - `skills/system-monitor/SKILL.md` 与 README 的 MCP 清单

   `catalog_covers_every_advertised_tool` 与 `docs_list_every_advertised_tool` 测试会卡住这三处不一致。
3. **默认只读**：MCP 默认 `readonly`；策略裁决在服务端，工具注解只是提示。破坏性动作（KILL、进程树、删除分组）必须按 L3 处理并支持一次性 `approval_token`。
4. **SSH 目标先校验**：远端主机必须经 `SshTarget::parse`，不得把用户输入拼进 shell；远端命令一律只读或经统一动作层。
5. **不提权**：GUI/TUI 本身不提权；tracefs 探针只经 root helper 的 unix socket（`scripts/install-probe-helper.sh`）。
6. **不伪造能力**：PSI、BTF、uprobe、memory cgroup 等不可用时必须显式标记 `unsupported`/原因，不能返回 0 或“看起来正常”的数据。远端采集失败要带 `stale` 与 `last_error`。
7. **测试隔离**：会写 `$HOME` 的测试用 `SM_HOME` 指向临时目录，并在触碰进程级环境变量时加全局锁；不要依赖真实用户目录内容。

## 实机约束（影响设计与测试）

- 目标树莓派为 cgroup v2，仅委派 `cpu` 与 `pids`；内核可能 `cgroup_disable=memory`，不要设计内存限额功能。
- BTF/uprobe/PSI 可能不可用；相关测试先探测再断言，缺能力时跳过而不是失败。
- 温度/功耗在树莓派来自 `vcgencmd`，其他主机走 hwmon / Intel RAPL（RAPL 需 root）。
- 采集路径要控制成本：`vcgencmd` 是子进程调用，`/proc` 全量扫描也不便宜；MCP 已有分层采样缓存（CPU 2s / 传感器 5s / 文件系统与连接 3s），新增工具应复用 `Server::view`、`local_usage`、`local_pi`、`local_aux`，不要各写一套采集。
- GPU 时钟不要走 debugfs 快路径：本机实测 `/sys/kernel/debug/dri/*/measure_clock` 单次读取约 1 秒，`read_gpu` 已改为优先 vcgencmd。

## 测试与文档约定

- 纯解析/换算/策略逻辑必须有单测；涉及时间、PID、随机性的逻辑尽量注入或提供确定性入口。
- 真实 SSH/cgroup/探针场景在 CI 中不可依赖；需要时用环境变量或能力探测 opt-in，并在输出中说明跳过原因。
- 修改 MCP 返回结构时同步 README 与 skill；错误信息保持结构化 JSON（AI 客户端依赖 `error` 字段）。
- 版本化设计记录在 `docs/superpowers/specs/`，实现计划在 `docs/superpowers/plans/`；不要另起一套文档目录。

## 提交前自查

- [ ] 上述构建/测试/clippy 全部通过（含 `--no-default-features`）
- [ ] 新 MCP 工具已在 `tools()`、`catalog()`、skill/README 同步
- [ ] 写操作仍经 dispatcher，风险等级与注解一致
- [ ] 失败路径有结构化错误与新鲜度标记，没有伪造数据
- [ ] 没有把真实主机名、token、密钥或用户数据写进测试与提交