# CPU 管理器 v2 设计增补（监控完善）

日期：2026-11-11
状态：用户指示「继续多做做 让其更加完善」并授权自主执行；本增补覆盖 v1 非目标中的「内存监控、历史曲线」两项（用户新指示优先）。
基线：v1 已交付（见 2026-11-10-cpu-manager-design.md），8/8 测试、clippy 干净、GUI 真机运行。

## 1. 目标

在 v1 基础上补齐日常监控最常用的维度：内存、系统负载/运行时长、CPU 历史走势、进程命令行，以及刷新控制。架构与依赖不变。

## 2. 功能需求

### 2.1 内存监控
- 顶部新增内存行：进度条 + 文本「已用 / 总量 GB」（1 位小数）。已用 = MemTotal − MemAvailable（/proc/meminfo，kB）。
- 进程表新增「内存MB」列（VmRSS，/proc/<pid>/status，kB→MB 1 位小数），位于 CPU% 之后；点表头排序，切到该列默认降序。内核线程无 VmRSS 显示 0.0。

### 2.2 系统信息行
- 顶部新增一行小字：负载 1/5/15 分钟（/proc/loadavg 前三个浮点，2 位小数）· 已运行时长（/proc/uptime 首字段秒数向下取整，格式「X天Y小时」/「X小时Y分」/「Y分Z秒」）· 进程总数。
- 任一文件读取失败则对应段不显示，不影响其他段。

### 2.3 CPU 历史曲线
- 顶部总占用右侧绘制最近 60 次采样（约 60 秒）的总 CPU% 走势 sparkline（约 200×36pt）：深色底 + 50% 参考线 + 折线；纵轴 0–100% 截断。
- 用 egui Painter 自绘（allocate_exact_size + line_segment），不加绘图依赖。
- 点数 ≥2 时按索引等距铺满宽度（x = i/(len−1)×宽），不足 2 点不画线；纵轴百分比 clamp 到 0–100。
- 历史缓冲 VecDeque<f32> 上限 60，每次采样推入；「暂停刷新」仅 gate 自动每秒 tick，期间点「立即刷新」或触发 ESRCH 重采样仍各推入一点（手动单次采样属预期）。

### 2.4 进程命令行
- 选中进程后过滤行下方显示一行小字「命令行: …」（/proc/<pid>/cmdline，NUL→空格，超 160 字符截断加 …）；未选中不显示。
- cmdline 为空（内核线程）回退显示「[名称]」。
- 结束/强制结束确认框在问题下方同样显示命令行（打开时现读），防误杀同名进程。
- cmdline 按需读取（选中变化/开确认框时），不进每秒全量快照。

### 2.5 刷新控制
- 过滤行右侧：「立即刷新」按钮（立即采样一次）；「暂停刷新/继续刷新」切换按钮（暂停时跳过每秒采样，历史不推入）。
- Delete 键：无对话框打开且选中进程可操作（非自身、非 PID 1）时，打开「结束进程」确认框（与按钮同路径）。
- 采样逻辑（采样+重置计时+历史推入+失效选中清理）收敛为唯一 `resample()` 方法，三处调用：每秒 tick、ESRCH 报告、立即刷新。

### 2.6 测试补强
- 新解析/格式化函数全部纯函数化并单测（fixture 文本）。
- 补终审遗留建议：Irix 模式进程 CPU% >100% 的单测（2 核满载 → 200%）。

## 3. 非目标（v2 仍不做）

进程树、磁盘/网络监控、系统托盘、配置持久化、每核历史曲线、多语言。

## 4. 数据层 API（procstats.rs，std only，全部纯函数可单测）

```rust
pub struct MemInfo { pub total_kb: u64, pub available_kb: u64 }
impl MemInfo { pub fn used_kb(self) -> u64; } // saturating_sub
pub fn parse_meminfo(text: &str) -> Option<MemInfo>; // 缺 MemTotal 或 MemAvailable → None

pub struct LoadAvg { pub one: f32, pub five: f32, pub fifteen: f32 }
pub fn parse_loadavg(text: &str) -> Option<LoadAvg>; // 前三浮点，不足 → None

pub fn parse_uptime(text: &str) -> Option<u64>; // 首字段 f64 向下取整
pub fn format_uptime(secs: u64) -> String; // 天/小时/分/秒分档

pub struct StatusFields { pub uid: Option<u32>, pub rss_kb: u64 }
pub fn parse_status(text: &str) -> StatusFields; // Uid: 首数字；VmRSS: kB；缺 VmRSS → 0
// read_uid 替换为 read_status(pid) -> StatusFields（读失败 → uid None, rss 0）

pub fn format_cmdline(bytes: &[u8]) -> String; // NUL→空格后 trim；空 → ""
pub fn read_cmdline(pid: i32) -> String; // 读失败 → ""

// 结构扩展（既有字段不动）：
ProcSnapshot  += rss_kb: u64
SystemSnapshot += mem: Option<MemInfo>, load: Option<LoadAvg>, uptime_secs: Option<u64>
ProcUsage     += rss_kb: u64
Usage         += mem/load/uptime_secs（compute 从 curr 透传，非差值）
```

- read_snapshot 增读 /proc/meminfo、/proc/loadavg、/proc/uptime（失败 → None）；每进程 status 只读一次同时取 Uid+VmRSS。
- compute 签名不变；procs 映射带 rss_kb；Usage 透传 curr 的 mem/load/uptime_secs。
- CPU% 口径、首采零值、消失进程跳过、saturating_sub 等 v1 语义全部不变。

## 5. UI 变更（app.rs / main.rs）

- 顶部面板四行：①标题+总%+条+sparkline ②每核条 ③内存条+GB 文本 ④负载·运行时长·进程数（小字）。窗口默认高度 620→700（main.rs）。
- 表格 7 列：PID/名称/用户/CPU%/内存MB/nice/状态；SortCol 加 Mem；内存列宽 80。
- 过滤行右侧加「立即刷新」「暂停刷新/继续刷新」；v1 过滤行的「共 N 个进程」挪到顶部信息行（不重复显示）；选中时过滤行下方一行 cmdline 小字。
- Confirm 结构加 cmdline 字段；开确认框统一走 `ask_confirm(kind, pid, comm)`（内部现读 cmdline，空回退 [comm]），按钮与 Delete 键三处调用。
- cmdline 缓存 `Option<(i32, String)>`：ui() 每帧检查选中 pid 与缓存 pid 不一致才重读；取消选中清缓存。
- 截断统一私有 helper `truncate_chars(s, 160)`（按 char 边界，避免切裂 UTF-8）。
- 暂停态 `paused: bool`；ui() tick 条件 `!paused && elapsed>=1s`。
- Delete 键处理在 ui() 开头：无对话框 + 选中可操作 + key_pressed(Delete) → ask_confirm(Terminate)。

## 6. 错误处理与安全

- 新增 /proc 文件读取失败一律降级（None/0/空串），不崩溃、不弹错。
- 调控安全语义不变：确认框、自身/PID 1 禁用、ESRCH 立即刷新（走 resample()）、EPERM 提示。
- Delete 键与按钮同路径同保护，不绕过确认。

## 7. 测试

- procstats 新增单测：parse_meminfo（正常/缺字段/垃圾）、parse_loadavg（正常/垃圾）、parse_uptime（正常/垃圾）、parse_status（Uid+VmRSS/无 VmRSS/垃圾）、format_cmdline（多参数/空/ trailing NUL）、format_uptime（天/小时/分/秒档）、compute Irix 200%、compute 透传（mem/load/uptime/rss）。
- 既有 8 测试保持全绿（fixture helper 补新字段）。
- actions 层不变，其 3 个集成测试不动。
- GUI：build 零警告 + clippy -D warnings 干净 + 真机冒烟（新行/新列/曲线/按钮可见可用）+ 用户验收。

## 8. 全局约束（沿用 v1）

- 无新依赖；无多线程；1s 采样；界面仅中文。
- 禁止 git 提交（本机无提交身份）；评审用快照 diff。
- 依赖版本不变（eframe/egui/egui_extras 0.37.0、nix 0.31.3、libc 0.2.191，lock 钉死）。
- egui 0.37 API 以 ~/.cargo/registry 源码为准（App::ui、Panel::top/bottom、Id::unique、selectable_label、Modal）。