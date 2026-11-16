# 性能基准与预算（#24）

## 测量方法

- `cargo bench --no-default-features` 运行 `benches/parse.rs`（零外部依赖的手写 harness）。
- 固定 fixture（`benches/fixtures/sample_blob.txt`：1000 进程、200 连接、4 核 stat），不依赖机器状态、SSH、特权操作。
- 每个路径 200 次预热 + 1000 次测量取**中位数**，输出 TSV（`name \t ns/op`）。
- CI `bench` job 保存 `estimates.json`（criterion 兼容文件未来接入）与本 harness 的 TSV 工件，供人工/脚本对比基线；超标（中位数 > 预算）时 job 失败。

## 预算

| 路径 | 预算（中位数） | 依据 |
| --- | --- | --- |
| 单条解析路径（远端整包/进程表/meminfo/net/df/PSI/目标校验） | 5 ms | 2s 采样周期、空闲 CPU < 1% 单核 = 20ms 预算，留 4 倍余量 |
| 采样整周期（含远端 SSH） | 10s 硬上限 | `remote::ssh_exec` 总超时（#3） |
| GUI 渲染 | 不因远端 I/O 阻塞 | #15：全部远端操作后台化 |

## 当前实测值（填写机器规格后更新）

CI 与本地各一次运行即生成；首次合入以 CI 工件为基线，回归判断=中位数劣化 > 30%。

## 机器规格（记录格式）

- CPU / 内存 / 内核：`uname -a` 输出
- 运行环境：bare metal / VM / container
