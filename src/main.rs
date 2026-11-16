// 纯 TUI 构建复用同一数据层，只用到其中一部分（cgroup / 网络连接 / 文件系统等留给 GUI 版），
// 因此非 gui 构建允许共享模块中暂未被 TUI 引用的条目。
#![cfg_attr(not(feature = "gui"), allow(dead_code))]

mod actions;
mod caps;
mod cgroup;
mod config;
mod fsutil;
mod mcp;
mod mcppolicy;
mod pi;
mod platform;
mod psi;
mod probe;
mod probeclient;
mod procstats;
mod remote;
mod schedstate;
mod sshtarget;
mod tui;
#[cfg(feature = "gui")]
mod app;
#[cfg(feature = "gui")]
mod scheduler;
#[cfg(feature = "gui")]
mod theme;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return;
    }
    if args.iter().any(|a| a == "mcp" || a == "--mcp") {
        if let Err(e) = mcp::run() {
            eprintln!("MCP 启动失败：{e}");
            std::process::exit(1);
        }
        return;
    }
    if args.first().is_some_and(|a| a == "mcp-approve") {
        mcp_approve(&args[1..]);
        return;
    }
    let want_tui = args.iter().any(|a| a == "--tui" || a == "--headless" || a == "-t");
    let has_display = std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some();
    let tui = cfg!(not(feature = "gui")) || want_tui || !has_display;
    if tui {
        if let Err(e) = tui::run() {
            eprintln!("TUI 启动失败：{e}");
            std::process::exit(1);
        }
    } else {
        gui_main();
    }
}

/// 签发 MCP L3 动作的一次性审批凭证（带外：由人在本机执行，token 转交给 AI 会话）。
/// 用法：system-monitor mcp-approve --tool process_signal --args '{"pid":123,"signal":"KILL"}' --ttl 60
fn mcp_approve(argv: &[String]) {
    let mut tool = String::new();
    let mut raw_args = String::new();
    let mut ttl: u64 = 60;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--tool" if i + 1 < argv.len() => {
                i += 1;
                tool = argv[i].clone();
            }
            "--args" if i + 1 < argv.len() => {
                i += 1;
                raw_args = argv[i].clone();
            }
            "--ttl" if i + 1 < argv.len() => {
                i += 1;
                ttl = argv[i].parse().unwrap_or(60);
            }
            other => {
                eprintln!("未知参数：{other}");
                print_approve_usage();
                std::process::exit(2);
            }
        }
        i += 1;
    }
    if tool.is_empty() {
        print_approve_usage();
        std::process::exit(2);
    }
    let args: serde_json::Value = if raw_args.trim().is_empty() {
        serde_json::json!({})
    } else {
        match serde_json::from_str(&raw_args) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("--args 不是合法 JSON：{e}");
                std::process::exit(2);
            }
        }
    };
    match mcppolicy::issue_approval(&tool, &args, ttl) {
        Ok(ap) => {
            println!("approval_token: {}", ap.token);
            println!("tool:  {tool}");
            println!("args:  {}", ap.params);
            let exp = ap.expires_at;
            println!("有效期至 unix {exp}（{ttl} 秒）；一次性使用，绑定以上参数。");
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

fn print_approve_usage() {
    eprintln!(
        "用法：system-monitor mcp-approve --tool <工具名> --args '<参数JSON>' --ttl <秒>\n\
         示例：system-monitor mcp-approve --tool process_signal --args '{{\"pid\":123,\"signal\":\"KILL\"}}' --ttl 60"
    );
}

fn print_help() {
    println!(
        "system-monitor {}\n\
         用法：system-monitor [--tui | mcp]\n\
         \n\
         --tui, --headless  终端界面（无图形环境时自动启用）\n\
         mcp, --mcp         以 MCP 服务运行（stdio，JSON-RPC）\n\
         -h, --help         显示本帮助\n\
         \n\
         图形版需要桌面会话（Wayland/X11）；本编译{}图形界面。\n\
         MCP 工具：hosts_list / host_use / system_overview / system_load /\n\
         process_list / process_signal / process_nice /\n\
         scheduler_groups / scheduler_set_limit / scheduler_group_action /\n\
         network_connections / filesystems / probe_status / probe_search /\n\
         probe_attach / probe_poll / probe_detach",
        env!("CARGO_PKG_VERSION"),
        if cfg!(feature = "gui") { "包含" } else { "未包含" }
    );
}

#[cfg(feature = "gui")]
fn gui_main() {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 880.0])
            .with_min_inner_size([1000.0, 640.0])
            .with_title("系统监视器"),
        ..Default::default()
    };
    if let Err(e) = eframe::run_native(
        "system-monitor",
        options,
        Box::new(|cc| Ok(Box::new(app::CpuManagerApp::new(cc)))),
    ) {
        eprintln!("图形界面启动失败：{e}");
        std::process::exit(1);
    }
}

#[cfg(not(feature = "gui"))]
fn gui_main() {}