mod actions;
mod app;
mod cgroup;
mod config;
mod pi;
mod platform;
mod probe;
mod probeclient;
mod procstats;
mod remote;
mod scheduler;
mod theme;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 820.0])
            .with_min_inner_size([960.0, 620.0])
            .with_title("系统监视器"),
        ..Default::default()
    };
    eframe::run_native(
        "system-monitor",
        options,
        Box::new(|cc| Ok(Box::new(app::CpuManagerApp::new(cc)))),
    )
}
