# 资源管理器 v4「调度中心」设计

**状态**：设计已确认，待实现
**日期**：2026-11-12
**作者**：与用户协作
**前序**：v1（CPU 监控 + 调控）、v2（增强）、v3（内存 + 树莓派能效/供电）

---

## 1. 概述与目标

在现有只读监控之上，增加一个「调度」视图：把**用户自己的进程**分进用户态 cgroup，
对每组施加 **CPU 硬上限**（`cpu.max`），并让温度/供电状态（来自 `pi.rs`）能驱动调度规则。

目标：
- **可控**：为自建分组设定可逆的 CPU 带宽上限，进程可加入/移出且能干净还原。
- **感知**：过热/欠压/降频时给出建议，可选自动节流（安全、可逆的动作）。
- **安全**：全程无 root、只作用于当前用户进程、默认只建议不自动动手、任何动作可一键解除。
- **内聚**：控制层、策略层、UI 层清晰分离，策略层纯逻辑可充分单测。

## 2. 非目标（受实机限制，非取舍）

- **内存预算**：内核 cmdline 含 `cgroup_disable=memory`，内存控制器全局禁用 → 任何方案都做不了。
- **系统/root 进程**：无 root 无法迁移或限制非本用户进程。
- **IO / cpuset**：这两个控制器未委派到用户子树（委派下来的只有 `cpu pids`）。
- **GPU / 网络**：不在范围。
- 不自动 kill / SIGSTOP（自动模式仅做可逆的 cpu.max / renice）。

## 3. 实机约束（已在目标机验证）

- cgroup 为 **v2 统一层级**，挂载于 `/sys/fs/cgroup`（`cgroup2fs`）。
- `user@<uid>.service` 为 `Delegate=yes`、属主为用户、**可写**；其 `cgroup.subtree_control` 已含 `cpu pids`。
- 当前用户 `uid=1000`，在 `sudo` 组（本设计**不使用** sudo）。
- 委派子树内可 `mkdir` 子 cgroup、写 `cpu.max/cpu.weight/pids.max`、把**本用户进程**写入 `cgroup.procs`。
- 应用进程当前位于 `user@1000.service/app.slice/app-*.scope`，其整条祖先链都在委派子树内。

## 4. 架构

新增两个模块，依赖方向：`app.rs → scheduler.rs`（策略）、`app.rs → cgroup.rs`（控制）；
`scheduler.rs` 不依赖 `cgroup.rs`（策略只产出「意图动作」，由 app 层执行）。全部零新依赖。

```
app.rs (UI + 执行编排)
 ├─ cgroup.rs   控制层：发现委派根、建组、设限、进程迁入/还原、读取组状态
 ├─ scheduler.rs 策略层：纯函数 evaluate(cfg, snapshot, state) -> Vec<Action>
 ├─ pi.rs       实况：温度/节流/供电
 └─ procstats.rs 实况：CPU/内存/进程
```

### 文件职责
- `src/cgroup.rs`：所有 cgroup 文件系统读写；纯换算/解析函数放这里便于单测。
- `src/scheduler.rs`：无 I/O 的策略引擎与状态机。
- `src/app.rs`：新增 `View::Scheduler` 视图与调度面板；resample 时驱动策略。

## 5. cgroup.rs 设计

### 5.1 路径发现
- 读 `/proc/self/cgroup`，取形如 `0::<path>` 的一行，得进程 cgroup 路径。
- 在路径段中定位 `user@<uid>.service`，其对应目录即**委派根** `base_root`。
- `base_root` 下创建容器目录 `cm-sched/`（已存在则复用）。
- 校验可用性：`base_root/cgroup.controllers` 含 `cpu` 且 `base_root` 可写；容器需能写入 `+cpu +pids`。
- 在容器 `cm-sched/cgroup.subtree_control` 写 `+cpu +pids`（容器本身不放进程，满足 no-internal-process 规则），
  使容器的子目录自动获得 `cpu.max/cpu.weight/pids.max`。

### 5.2 公共 API
```rust
pub struct CgroupManager { root: PathBuf, container: PathBuf } // root=委派根, container=cm-sched

pub enum CgError { NotDelegated, Permission, Gone, Io(String), Invalid(String) }

impl CgroupManager {
    pub fn detect() -> Result<CgroupManager, CgError>;
    pub fn list_groups(&self) -> Result<Vec<GroupState>, CgError>;
    pub fn create_group(&self, name: &str) -> Result<(), CgError>;
    pub fn delete_group(&self, name: &str) -> Result<(), CgError>;
    pub fn set_cpu_max(&self, name: &str, pct: Option<u32>) -> Result<(), CgError>; // None = 不限
    pub fn set_cpu_weight(&self, name: &str, weight: u32) -> Result<(), CgError>;   // 1..=10000
    pub fn set_pids_max(&self, name: &str, max: Option<u32>) -> Result<(), CgError>; // None = 不限
    /// 返回该进程迁入前的原始 cgroup 目录（供还原）
    pub fn move_in(&self, name: &str, pid: i32) -> Result<PathBuf, CgError>;
    pub fn release(&self, pid: i32, original: &Path) -> Result<(), CgError>;
    pub fn group_of(&self, pid: i32) -> Option<String>;
}

pub struct GroupState {
    pub name: String,
    pub cpu_max_pct: Option<u32>, // None=不限
    pub cpu_weight: u32,
    pub pids_max: Option<u32>,
    pub procs: usize,
}

// 纯函数（单测重点，不碰真机）
pub fn parse_self_cgroup(text: &str, uid: u32) -> Option<PathBuf>;
pub fn pct_to_cpu_max(pct: u32) -> String;       // 50 -> "50000 100000"
pub fn parse_cpu_max(text: &str) -> Option<u32>; // "50000 100000" -> 50; "max ..." -> None
```

### 5.3 文件格式
- `cpu.max`：`"<quota> <period>"`，period 固定 `100000` µs。`pct` 指**单核百分比**：
  `quota = pct * 1000`（50%→50000）。不限写 `"max 100000"`。
- `cpu.weight`：整数 `1..=10000`，默认 100。
- `pids.max`：整数或 `"max"`。
- 迁入：把 pid 十进制串写目标组 `cgroup.procs`。
- 还原：把 pid 写回**原始 cgroup 目录**的 `cgroup.procs`；若原目录已消失，回落到容器内一个不限组 `default`。

### 5.4 校验与安全
- `move_in`/`release` 前读 `/proc/<pid>/status` 的 `Uid:`，必须等于本进程 uid；`pid==1`、`pid==自身`、内核线程一律拒绝（`Invalid`）。
- 组名做白名单校验：仅 `[A-Za-z0-9._-]`，长度 1..=64，禁止 `/`、`..`。
- 所有路径都拼在 `container/` 之下，杜绝路径穿越。

## 6. scheduler.rs 设计

### 6.1 数据结构
```rust
pub struct Config {
    pub enabled: bool,          // 自动模式总开关（默认 false）
    pub temp_high: f32,         // 默认 80.0，触发节流
    pub temp_low: f32,          // 默认 70.0，回差释放
    pub throttle_pct: u32,      // 默认 50（单核百分比）
    pub target_group: Option<String>,
    pub cooldown_secs: u64,     // 默认 20，两次状态切换最短间隔
}

pub struct Snapshot { pub temp_c: Option<f32>, pub throttled: bool, pub undervoltage: bool }

pub enum Action {
    Engage { group: String, pct: u32 },
    Restore { group: String },
    None,
}

pub struct State { pub engaged: bool, pub last_change: Option<Instant> }

pub fn evaluate(cfg: &Config, snap: &Snapshot, st: &mut State, now: Instant) -> Vec<Action>;
```

### 6.2 判定语义（带回差 + 冷却）
- 若 `!cfg.enabled` 或 `target_group` 为 None → 返回空（不干预）。
- **投入**：`!engaged` 且（`temp >= temp_high` 或 `snap.throttled` 或 `snap.undervoltage`）
  且冷却已过 → `Engage{group, throttle_pct}`，置 `engaged=true`，记录 `last_change`。
- **释放**：`engaged` 且 `temp <= temp_low` 且 `!throttled` 且 `!undervoltage`
  且冷却已过 → `Restore{group}`，置 `engaged=false`，记录 `last_change`。
- 其余情况返回空。`now` 由调用方注入，便于测试冷却逻辑。

### 6.3 app 层执行
- resample 后，若 `cfg.enabled`，调 `evaluate`，对 `Engage`→`set_cpu_max(group, Some(pct))`，
  `Restore`→`set_cpu_max(group, None)`；结果写状态栏。
- 建议模式（`enabled=false`）：仅在界面用当前 snapshot 计算「是否该节流」，展示建议横幅 + 一键应用，不自动执行。

## 7. app.rs UI 设计

### 7.1 视图切换
- 顶栏下加一个分段切换：`监控` | `调度`（枚举 `View`，默认 `监控`）。`调度` 时中央区显示调度面板。
- 监控视图保持现有内容不变（表格、右键菜单、快捷键）。

### 7.2 调度面板
- **状态横幅**：绿色「可调度（cpu/pids）」或红色原因（如「当前不在可委派 cgroup 子树内」）；不可用时控件置灰。
- **分组列表**：每组一行——名称、CPU 上限（不限/xx%）、进程数、`删除`；顶部「新建分组」名称输入 + 按钮。
- **加入进程**：显示当前选中进程（来自监控视图的选择，选择跨视图保留）；分组下拉 + `加入`；`移出`（还原到原 cgroup）。
- **CPU 上限**：对选中分组给预设按钮 `25% / 50% / 100% / 200% / 不限`，点即 `set_cpu_max`。
- **规则卡片**：自动模式开关、`temp_high/temp_low` 滑块、目标分组下拉、节流百分比、`解除全部限速` 按钮
  （对所有分组 `set_cpu_max(None)` 并把托管进程还原）。

## 8. 数据流

`resample()`（沿用现有 `interval` 节奏）：
1. 读 `pi stats` + `usage`（现状）。
2. 若调度可用，`list_groups()` 刷新分组状态（轻量目录读）。
3. 自动模式下 `scheduler::evaluate` → 执行动作 → 更新状态栏。
4. UI 每帧只渲染已缓存的状态，不做重 I/O。

## 9. 安全护栏（硬规则）

- 永不操作 `pid==1`、自身 pid、非本用户进程（预检 `Uid`）。
- 所有限制可逆；`解除全部限速` 恢复 `cpu.max` 并还原托管进程。
- 自动模式默认关；只做 `cpu.max` 收紧/放宽，绝不 kill/stop。
- 委派不可用/写失败 → 状态栏报错、控件禁用、监控照常，不 panic。
- 测试**只**迁移本进程 spawn 的 `sleep` 子进程，绝不碰用户真实进程。

## 10. 错误处理

- `CgError` 映射为中文状态消息；`Permission` 提示「需在用户会话内运行」。
- 所有 fs 操作返回 `Result`，不 `unwrap` 真机路径；纯函数解析失败返回 `Option`。
- 旧组残留、目录已存在、`rmdir` 失败（组内仍有进程）→ 明确提示。

## 11. 测试策略（TDD）

- **纯函数单测**（`cgroup.rs`）：`parse_self_cgroup`（多种 `/proc/self/cgroup` 输入）、
  `pct_to_cpu_max`/`parse_cpu_max`（往返）、组名校验。
- **真机冒烟**（`cgroup.rs`，守卫式）：仅当 `detect()` 成功时执行——
  建 `cm-sched-test-<pid>` 组、设 50%、把 spawn 的 `sleep` 迁入、读回 `cpu.max` 与组内进程数、
  还原并删组；失败则 `eprintln` 跳过，不失败整套（沿用 `pi::read_pi_stats` 冒烟风格）。
- **策略单测**（`scheduler.rs`，TDD 主体）：投入/释放/回差/冷却/未启用/无目标组 等分支，
  用注入的 `now` 精确控制时间。

## 12. 交付与验证

- `cargo build --release` 零警告；`clippy --release --all-targets -- -D warnings` 干净；
  `cargo test --bin cpu-manager` 全绿（含新增纯函数与策略测试）。
- 重拉 GUI、`grim` 截图核对调度面板渲染；不提交 git（无提交身份约束）。
- 诚实说明：Wayland 下无法注入鼠标点击，交互路径靠编译 + 测试 + 静态截图 + 源码核对确认。

## 13. 风险与边界

- 迁入进程会改变其 cgroup 归属；本设计通过记录原路径保证可还原，但若原 scope 在进程存活期被销毁则不保证。
- systemd 可能对 `user@` 下非其管理的子目录有未知行为；缓解：容器命名 `cm-sched` 明确归属，且不触碰 `app.slice` 等 systemd 目录。
- 控制器启用失败（容器内已有进程）需自愈：先迁空再启用。

## 14. 未来（v5，非本期）

- 若能移除内核 `cgroup_disable=memory` 并重启（需用户单独批准），可加内存预算。
- 更丰富的规则（按进程名/负载触发、多条件组合）、调度历史与图表。
- 可选 sudo 助手以管理系统进程（独立安全评估后再议）。
```