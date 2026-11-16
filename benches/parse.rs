//! 核心路径基准（#24）：固定 fixture、无 SSH、无特权、零外部依赖。
//! 每个基准取 MEASURE 次的中位数 ns/op，输出机器可解析 TSV。
//! 预算与机器规格见 docs/performance.md；任何路径中位数 > 5ms 即失败退出
//! （解析预算 = 1% 单核 @ 2s 采样周期 = 20ms，留 4 倍余量）。

use std::time::Instant;

use system_monitor::{procstats, psi, remote, sshtarget};

const SAMPLE_BLOB: &str = include_str!("fixtures/sample_blob.txt");
const WARMUP: usize = 200;
const MEASURE: usize = 1000;
/// 单路径中位数预算：5ms（解析路径预算 20ms 的 1/4）。
const BUDGET_NS: u128 = 5_000_000;

fn bench<F: FnMut()>(name: &str, mut f: F) -> (String, u128) {
    for _ in 0..WARMUP {
        f();
    }
    let mut samples = Vec::with_capacity(MEASURE);
    for _ in 0..MEASURE {
        let t = Instant::now();
        f();
        samples.push(t.elapsed().as_nanos());
    }
    samples.sort_unstable();
    let med = samples[samples.len() / 2];
    println!("{name}\t{med}\tns/op");
    (name.to_string(), med)
}

fn main() {
    let sec = |k: &str| {
        SAMPLE_BLOB
            .split(&format!("##{k}\n"))
            .nth(1)
            .unwrap_or("")
            .split("##")
            .next()
            .unwrap_or("")
            .to_string()
    };

    let mut results = Vec::new();

    // 1. 远端整包解析（含差分）
    results.push(bench("remote/parse_output", || {
        let mut prev = None;
        let _ = remote::parse_output(SAMPLE_BLOB, &mut prev);
    }));

    // 2. 进程表解析
    let ps = sec("ps");
    results.push(bench("remote/parse_ps", || {
        let _ = remote::parse_ps(&ps);
    }));

    // 3. meminfo
    let mem = sec("mem");
    results.push(bench("procstats/parse_meminfo", || {
        let _ = procstats::parse_meminfo(&mem);
    }));

    // 4. /proc/net/tcp
    let tcp = sec("tcp");
    results.push(bench("procstats/parse_proc_net", || {
        let _ = procstats::parse_proc_net(&tcp, "TCP");
    }));

    // 5. df
    let df = sec("df");
    results.push(bench("procstats/parse_df", || {
        let _ = procstats::parse_df(&df);
    }));

    // 6. PSI 解析
    let pressure = "some avg10=1.23 avg60=4.56 avg300=7.89 total=123456789\nfull avg10=0.10 avg60=0.20 avg300=0.30 total=999\n";
    results.push(bench("psi/parse_resource", || {
        let _ = psi::parse_psi_resource(pressure);
    }));

    // 7. SSH 目标校验
    results.push(bench("sshtarget/parse", || {
        let _ = sshtarget::SshTarget::parse("user@example-host.example.org");
    }));

    let mut bad = 0;
    for (name, ns) in &results {
        if *ns > BUDGET_NS {
            eprintln!("BUDGET-EXCEEDED\t{name}\t{ns}ns");
            bad += 1;
        }
    }
    if bad > 0 {
        std::process::exit(1);
    }
    println!("SUMMARY\tall_paths_within_budget");
}
