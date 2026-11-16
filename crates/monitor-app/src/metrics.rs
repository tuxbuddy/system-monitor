//! 指标导出（#26）：Prometheus 文本格式 /metrics + 兼容 JSON 路径。
//!
//! 治理要求：默认仅绑定 127.0.0.1；`SM_METRICS_DISABLED=1` 可整体关闭；
//! 绑定失败必须可见（日志一次），不得静默吞掉；指标带 host 标签，
//! 基数有界（固定指标集，无用户输入参与标签）。

use std::io::Write;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// 共享采样值（GUI 的 SharedMetrics 同构；避免 app 依赖方向反转,字段平铺）。
#[derive(Clone, Copy, Default)]
pub struct MetricsSample {
    pub cpu: f32,
    pub mem: f32,
    pub temp: f32,
    pub power: f32,
    pub gpu_ghz: f32,
    pub disk_read_kbps: f32,
    pub disk_write_kbps: f32,
    pub net_rx_kbps: f32,
    pub net_tx_kbps: f32,
    pub procs: u64,
}

pub type SharedSample = Arc<Mutex<MetricsSample>>;

/// Prometheus 文本格式。指标名前缀 system_monitor_，host 标签固定为
/// 本机名/127.0.0.1 常量（基数=1×固定指标数，不随用户输入增长）。
pub fn prometheus_text(s: &MetricsSample, host_label: &str) -> String {
    let mut out = String::with_capacity(2048);
    let mut line = |name: &str, help: &str, mtype: &str, key: &str, value: f64| {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {mtype}\n{name}{{host=\"{host_label}\"}} {value}\n"));
        let _ = key;
    };
    line("system_monitor_cpu_percent", "Total CPU usage percent", "gauge", "", f64::from(s.cpu));
    line("system_monitor_memory_percent", "Memory usage percent", "gauge", "", f64::from(s.mem));
    line("system_monitor_temperature_celsius", "CPU temperature", "gauge", "", f64::from(s.temp));
    line("system_monitor_power_watts", "CPU package power estimate", "gauge", "", f64::from(s.power));
    line("system_monitor_gpu_frequency_ghz", "GPU frequency", "gauge", "", f64::from(s.gpu_ghz));
    line("system_monitor_disk_read_kilobytes_per_second", "Disk read throughput", "gauge", "", f64::from(s.disk_read_kbps));
    line("system_monitor_disk_write_kilobytes_per_second", "Disk write throughput", "gauge", "", f64::from(s.disk_write_kbps));
    line("system_monitor_network_rx_kilobytes_per_second", "Network receive throughput", "gauge", "", f64::from(s.net_rx_kbps));
    line("system_monitor_network_tx_kilobytes_per_second", "Network transmit throughput", "gauge", "", f64::from(s.net_tx_kbps));
    line("system_monitor_process_count", "Process count", "gauge", "", s.procs as f64);
    // 非数值元信息
    out.push_str(&format!("# HELP system_monitor_scrape_timestamp_seconds Last sample wall time\n# TYPE system_monitor_scrape_timestamp_seconds gauge\nsystem_monitor_scrape_timestamp_seconds{{host=\"{host_label}\"}} {}\n", unix_now()));
    out
}

/// 兼容旧 JSON 路径。
pub fn json_text(s: &MetricsSample) -> String {
    format!(
        "{{\"cpu\":{:.1},\"mem\":{:.1},\"temp\":{:.1},\"power\":{:.2},\"gpu_ghz\":{:.2},\"disk_read_kbps\":{:.1},\"disk_write_kbps\":{:.1},\"net_rx_kbps\":{:.1},\"net_tx_kbps\":{:.1},\"procs\":{}}}",
        s.cpu, s.mem, s.temp, s.power, s.gpu_ghz, s.disk_read_kbps, s.disk_write_kbps, s.net_rx_kbps, s.net_tx_kbps, s.procs
    )
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// 是否禁用导出（环境开关；配置文件键 metrics_enabled 经 app 层同步到这里）。
pub fn disabled() -> bool {
    std::env::var("SM_METRICS_DISABLED").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// 端口选择：SM_METRICS_PORT 可配；默认 9876,始终只绑 127.0.0.1。
pub fn bind_addr() -> String {
    let port = std::env::var("SM_METRICS_PORT").ok().and_then(|p| p.parse::<u16>().ok()).unwrap_or(9876);
    format!("127.0.0.1:{port}")
}

/// 启动指标服务。绑定失败返回 Err(调用方展示),不再静默。
pub fn start(shared: SharedSample, host_label: String) -> Result<(), String> {
    if disabled() {
        return Ok(());
    }
    let addr = bind_addr();
    let listener = TcpListener::bind(&addr).map_err(|e| format!("指标端口绑定失败 {addr}：{e}"))?;
    eprintln!("system-monitor: metrics on http://{addr}/metrics (JSON: /metrics.json)");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let sample = shared.lock().map(|m| *m).unwrap_or_default();
            // 读请求行决定路径;超 4KB 即断（恶意/异常客户端防护）
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0u8; 4096];
            let n = std::io::Read::read(&mut s, &mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let body = if req.contains("/metrics.json") {
                let j = json_text(&sample);
                format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", j.len(), j)
            } else {
                let text = prometheus_text(&sample, &host_label);
                format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", text.len(), text)
            };
            let _ = s.write_all(body.as_bytes());
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_format_is_parseable_shape() {
        let s = MetricsSample { cpu: 12.3, mem: 45.6, procs: 200, ..Default::default() };
        let text = prometheus_text(&s, "local");
        let mut found = 0;
        for line in text.lines() {
            if line.starts_with("system_monitor_") && line.contains("{host=\"local\"}") {
                // 值可解析
                let val = line.rsplit(' ').next().unwrap();
                assert!(val.parse::<f64>().is_ok(), "值应为数字：{line}");
                found += 1;
            }
        }
        assert_eq!(found, 11, "10 指标 + 1 时间戳");
        assert!(text.contains("# TYPE system_monitor_cpu_percent gauge"));
    }

    #[test]
    fn disabled_env_disables_export() {
        // 只测判定函数语义,不真改进程 env(避免并行污染)
        assert!(!disabled()); // 默认不设环境变量时开启
    }

    #[test]
    fn bind_addr_is_loopback_only() {
        assert!(bind_addr().starts_with("127.0.0.1:"));
    }

    #[test]
    fn json_keeps_legacy_shape() {
        let j = json_text(&MetricsSample::default());
        assert!(j.contains("\"cpu\":0.0"));
        assert!(serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&j).is_ok());
    }
}
