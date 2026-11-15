# CPU 管理器 v3 设计文档（内存扩展 + 能效/供电监控）

日期：2026-11-11
环境：Raspberry Pi 500 Rev 1.0 / Debian 13 arm64 / Wayland / BCM2712 4 核
状态：用户指示「继续进行演进 把内存啥的都弄出来 以及能效 供电啥的」，既有自主端到端授权覆盖审批门，呈现设计后直接推进。

## 1. 目标

在 v2（CPU/进程/内存条/历史曲线/命令行/刷新控制）基础上：
- 把内存监控做全：系统内存细分（空闲/缓冲/缓存）、Swap、每进程内存占比。
- 新增 Pi 500 能效与供电监控：SoC 温度、CPU 频率、核心功耗（真实瓦数）、供电输入电压、节流/欠压状态。

## 2. 硬件数据源（已实测确认）

| 数据 | 来源 | 单位/形态 | 实测样例 |
|---|---|---|---|
| SoC 温度 | `/sys/class/thermal/thermal_zone0/temp` | 毫摄氏度整数 | `50700` → 50.7°C |
| CPU 频率 | `/sys/devices/system/cpu/cpuN/cpufreq/scaling_cur_freq` | kHz 整数 | `2400000` → 2.4GHz |
| PMIC 各 rail 电压/电流 | `vcgencmd pmic_read_adc` | 文本行 `LABEL volt(N)=X.XV` / `LABEL current(N)=X.XA` | `VDD_CORE_V volt(15)=0.86495640V`、`VDD_CORE_A current(7)=2.73258000A`、`EXT5V_V volt(24)=5.10138000V` |
| 节流/欠压标志 | `vcgencmd get_throttled` | `throttled=0x<hex>` | `throttled=0x0` |
| 内存细分 | `/proc/meminfo` | kB | MemFree/Buffers/Cached/SwapTotal/SwapFree |

关键约束：
- **sysfs 不暴露电流/功耗**（hwmon 只有温度与电压，无 curr/power），真实瓦数与完整节流标志只能经 `vcgencmd`。`/usr/bin/vcgencmd` 本机可用，普通用户无需 sudo。
- `/sys/class/power_supply/` 为空（Pi 500 无电池/USB-PD class），不使用该来源。
- 温度/频率走 sysfs 纯文件读（稳、无子进程）；功耗/节流走 vcgencmd 子进程（每秒 2 次，轻量本地固件调用）。

## 3. 功能需求

### 3.1 内存扩展
- 内存行：内存条 + `已用/总 GB`，并排新增 **Swap 条** + `已用/总 MB`。
- 可折叠「内存详情」（默认收起）：空闲/缓冲/缓存（MB）、Swap 已用/总（MB）。
- 进程表新增「内存%」列（rss/总内存×100），可点表头排序（默认降序）。

### 3.2 能效/供电
- 顶部新增**能效/供电行**：`温度 XX.X°C · 频率 X.XX GHz · 核心功耗 X.XX W · 供电 X.XX V`。
  - 频率 = 各核 scaling_cur_freq 的平均值（GHz）。
  - 核心功耗 = VDD_CORE_V × VDD_CORE_A（W）；供电 = EXT5V_V（输入 5V rail 电压）。
  - 任一来源缺失 → 该项显示「—」，不崩溃。
- 节流状态：正常显示绿色「供电正常」；当前任一标志置位显示红色警告（欠压/降频/节流/温度限制）；仅历史标志置位显示「曾发生 throttling（历史）」。
- 可折叠「供电详情」（默认收起）：列出各 rail 的 `名称: V × A = W`。

### 3.3 节流位标志解码（vcgencmd get_throttled）
- bit0 欠压（当前）、bit1 降频（当前）、bit2 节流（当前）、bit3 软温度限制（当前）。
- bit16–19 对应历史标志；`occurred = (bits >> 16) & 0xF != 0`。

## 4. 非目标（YAGNI）
- 整板总功耗求和（rail 嵌套供电，求和重复计算、误导）——只报核心功耗 + 各 rail 明细。
- 性能/瓦特比、历史功耗曲线、风扇控制（Pi 500 无风扇 class）、电池/UPS 监控。
- 每核频率明细列（headline 平均值足够）。
- 磁盘/网络监控（沿用 v1 非目标）。

## 5. 架构与数据流

```
src/procstats.rs  /proc 数据层：扩展 MemInfo + ProcUsage.mem_percent（纯函数 + 单测）
src/pi.rs         新模块：Pi 硬件传感器（sysfs 温度/频率 + vcgencmd 功耗/节流），纯解析器与 IO 分离
src/app.rs        egui App：能效/供电行、内存 Swap+详情、供电详情、内存% 列
src/main.rs       加 mod pi；窗口高度按需调整
```

### 5.1 procstats.rs 扩展
```rust
pub struct MemInfo {           // 新增 free/buffers/cached/swap_total/swap_free
    pub total_kb: u64, pub available_kb: u64,
    pub free_kb: u64, pub buffers_kb: u64, pub cached_kb: u64,
    pub swap_total_kb: u64, pub swap_free_kb: u64,
}
impl MemInfo {
    pub fn used_kb(self) -> u64;       // 既有
    pub fn swap_used_kb(self) -> u64;  // swap_total - swap_free（saturating）
}
pub fn parse_meminfo(text) -> Option<MemInfo>;  // 仍要求 MemTotal+MemAvailable，其余缺省 0
pub struct ProcUsage { /* …既有… */ pub mem_percent: f32 }  // 新增
// compute：mem_percent = rss_kb / curr.mem.total_kb × 100（total=0 → 0）
```
- `Usage.mem` 已是 `Option<MemInfo>`，扩展字段自动透传。
- **既有测试修正**：`compute_passthrough_mem_load_uptime_rss` 构造 `MemInfo { total_kb, available_kb }` 须改 `..Default::default()`（新增字段否则编译失败）。

### 5.2 pi.rs（新模块）
```rust
pub struct Rail { pub name: String, pub volts: f32, pub amps: f32 }
impl Rail { pub fn watts(&self) -> f32 { self.volts * self.amps } }

pub struct Power { pub core_v: f32, pub core_a: f32, pub core_w: f32, pub ext5v_v: f32 }

pub struct Throttle {
    pub undervoltage: bool, pub freq_capped: bool, pub throttled: bool,
    pub soft_temp_limit: bool, pub occurred: bool,
}
impl Throttle {
    pub fn any_current(self) -> bool;
    pub fn warning(self) -> String;   // 拼接当前标志中文 + 历史后缀
}

pub struct PiStats {
    pub temp_c: Option<f32>, pub freq_ghz: Option<f32>,
    pub power: Option<Power>, pub throttle: Option<Throttle>,
    pub rails: Vec<Rail>,
}

// 纯解析器（单测，fixture 取实测输出）
pub fn parse_temp_millideg(text: &str) -> Option<f32>;   // 首 token i64 /1000
pub fn parse_freq_khz(text: &str) -> Option<u64>;        // 首 token u64
pub fn parse_pmic(text: &str) -> Vec<Rail>;              // 按 _V/_A 去后缀配对 base name
pub fn power_summary(rails: &[Rail]) -> Power;           // 取 VDD_CORE/EXT5V
pub fn parse_throttled(text: &str) -> Option<Throttle>;  // 提取 0x hex 解码位

// IO 包装（失败 → None/空，优雅降级）
pub fn read_pi_stats() -> PiStats;
fn run_vcgencmd(args: &[&str]) -> Option<String>;        // Command::output，非 0 退出 → None
```
- `parse_pmic`：逐行取首 token 为 label，按结尾 `_V`/`_A` 分类，base = 去后缀；同 base 的 V/A 合并为一个 Rail；值取 `=` 后去掉单位尾字符（V/A）parse f32。
- `read_pi_stats`：sysfs 读温度/频率（频率枚举 cpuN 目录取平均）；vcgencmd 读 pmic/get_throttled；rails 空 → power None。

### 5.3 app.rs 集成
- 新字段 `pi: PiStats`；`resample()` 内 `self.pi = pi::read_pi_stats();`（与采样同节奏，每秒一次）。
- top_panel：内存行加 Swap 条；新增能效/供电行 + 节流状态；新增「内存详情」「供电详情」两个 CollapsingHeader（默认收起）。
- 进程表：新增 `SortCol::MemPct` 与「内存%」列（exact 60），排序 `a.mem_percent.partial_cmp`，默认降序同 Cpu/Mem。
- egui 0.37 API：`CollapsingHeader::new(text).default_open(false).show(ui, |ui| …)`（计划阶段对照 registry 源码核验）。

## 6. 错误处理与降级
- vcgencmd 不在 PATH / 非 0 退出 / 输出非法 → power/throttle = None，UI 显示「—」；温度/频率（sysfs）不受影响。
- sysfs 温度/频率读失败 → 对应 None → 「—」。
- pmic 解析不出任何 rail → rails 空、power None。
- 子进程 `Command::output()` 阻塞至 vcgencmd 返回（本地固件调用，毫秒级）；不设超时（YAGNI），失败回 None 不崩。
- 沿用 v2 安全语义：调控按钮/确认框/Delete 守卫/ESRCH 即时刷新/EPERM 提示均不变。

## 7. 测试
- procstats 单测：parse_meminfo 扩展字段 + swap_used；compute_mem_percent（rss/total×100，total=0→0）；修正 compute_passthrough 的 MemInfo 构造。
- pi.rs 单测：parse_temp_millideg（50700→50.7、garbage→None）；parse_freq_khz；parse_pmic（实测 fixture 子集→VDD_CORE/EXT5V 配对）；power_summary（core_w≈v×a）；parse_throttled（0x0 全 false、0x50005 解码 bit0/2/16/18、garbage→None）；Throttle::any_current/warning。
- IO 冒烟：真机 read_pi_stats 返回 Some 温度/频率/功耗/节流。
- GUI：cargo build 零警告 + clippy --all-targets -D warnings + 全量 test + 真机启动冒烟（能效行有数、内存详情/供电详情可展开、内存% 列可排序）+ 用户验收。

## 8. 构建与运行
- 沿用 v2：cargo run / cargo build --release；桌面启动器不变（Exec 指向 release 产物）。
- 无新增 crate 依赖（vcgencmd 是系统命令，经 std::process::Command 调用；sysfs/proc 经 std::fs）。
- 无 git 提交（本机无提交身份，沿用快照 diff 评审）。