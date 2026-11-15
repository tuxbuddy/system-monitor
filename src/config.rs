use std::path::PathBuf;

/// 持久化的界面/阈值设置；纯文本 key=value，写入 ~/.config/system-monitor/config.conf。
/// 不依赖 eframe 的 persistence 特性（那会引入额外依赖）。
#[derive(Clone, PartialEq, Debug)]
pub struct AppConfig {
    pub sort_col: String,
    pub sort_desc: bool,
    pub interval: f32,
    pub table_mode: String,
    pub own_only: bool,
    pub alert_cpu: f32,
    pub alert_mem: f32,
    pub alert_temp: f32,
    /// 顶部大盘（KPI 卡片行）是否展开。
    pub dash_open: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            sort_col: "cpu".to_string(),
            sort_desc: true,
            interval: 1.0,
            table_mode: "flat".to_string(),
            own_only: false,
            alert_cpu: 90.0,
            alert_mem: 90.0,
            alert_temp: 80.0,
            dash_open: true,
        }
    }
}

impl AppConfig {
    pub fn to_text(&self) -> String {
        format!(
            "sort_col={}\nsort_desc={}\ninterval={}\ntable_mode={}\nown_only={}\nalert_cpu={}\nalert_mem={}\nalert_temp={}\ndash_open={}\n",
            self.sort_col,
            self.sort_desc,
            self.interval,
            self.table_mode,
            self.own_only,
            self.alert_cpu,
            self.alert_mem,
            self.alert_temp,
            self.dash_open
        )
    }
}

pub fn parse(text: &str) -> AppConfig {
    let mut c = AppConfig::default();
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let k = k.trim();
        let v = v.trim();
        match k {
            "sort_col" => c.sort_col = v.to_string(),
            "sort_desc" => {
                if v == "true" {
                    c.sort_desc = true;
                } else if v == "false" {
                    c.sort_desc = false;
                }
            }
            "interval" => {
                if let Ok(x) = v.parse() {
                    c.interval = x;
                }
            }
            "table_mode" => c.table_mode = v.to_string(),
            "own_only" => {
                if v == "true" {
                    c.own_only = true;
                } else if v == "false" {
                    c.own_only = false;
                }
            }
            "alert_cpu" => {
                if let Ok(x) = v.parse() {
                    c.alert_cpu = x;
                }
            }
            "alert_mem" => {
                if let Ok(x) = v.parse() {
                    c.alert_mem = x;
                }
            }
            "alert_temp" => {
                if let Ok(x) = v.parse() {
                    c.alert_temp = x;
                }
            }
            "dash_open" => {
                if v == "true" {
                    c.dash_open = true;
                } else if v == "false" {
                    c.dash_open = false;
                }
            }
            _ => {}
        }
    }
    c
}

pub fn path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".config/system-monitor/config.conf"))
}

pub fn load() -> AppConfig {
    match path().and_then(|p| std::fs::read_to_string(p).ok()) {
        Some(text) => parse(&text),
        None => AppConfig::default(),
    }
}

pub fn save(c: &AppConfig) {
    let Some(p) = path() else {
        return;
    };
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(p, c.to_text());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let c = AppConfig {
            sort_col: "mem".into(),
            sort_desc: false,
            interval: 2.0,
            table_mode: "tree".into(),
            own_only: true,
            alert_cpu: 85.0,
            alert_mem: 80.0,
            alert_temp: 75.0,
            dash_open: false,
        };
        assert_eq!(parse(&c.to_text()), c);
    }

    #[test]
    fn defaults_and_bad_lines() {
        let c = parse("garbage\nsort_desc=maybe\ninterval=abc\n");
        assert_eq!(c, AppConfig::default());
        let c = parse("interval=5\n");
        assert!((c.interval - 5.0).abs() < 1e-6);
    }
}