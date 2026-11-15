//! 系统监视器视觉系统：从树莓派系统监控主题派生的暗色仪表盘配色。
//! 背景取服务器机架/示波器的冷调石板色，强调色对应被监控的物理量：
//! CPU=青色信号、内存= teal 绿、供电=琥珀、温度=绿→琥珀→红渐变。

use std::collections::BTreeMap;

use eframe::egui::{self, Color32, CornerRadius, Margin, Shadow, Stroke, Vec2};

// ---- 背景层级 ----
pub const BG: Color32 = Color32::from_rgb(13, 17, 23); // 面板底
pub const SURFACE: Color32 = Color32::from_rgb(22, 27, 34); // 卡片
pub const ELEVATED: Color32 = Color32::from_rgb(28, 33, 40); // 弹窗/窗口
pub const EXTREME: Color32 = Color32::from_rgb(10, 14, 19); // 文本框/滚动条轨道/迷你图底
pub const FAINT: Color32 = Color32::from_rgb(18, 23, 30); // 表格斑马纹

// ---- 边框 ----
pub const BORDER: Color32 = Color32::from_rgb(38, 44, 54);
pub const BORDER_STRONG: Color32 = Color32::from_rgb(54, 61, 71);

// ---- 文字层级 ----
pub const TEXT: Color32 = Color32::from_rgb(230, 237, 243); // 主
pub const TEXT_SEC: Color32 = Color32::from_rgb(167, 179, 192); // 次
pub const TEXT_MUTED: Color32 = Color32::from_rgb(110, 123, 138); // 弱

// ---- 强调色（对应物理量）----
pub const CPU: Color32 = Color32::from_rgb(76, 194, 255); // 青
pub const MEM: Color32 = Color32::from_rgb(63, 214, 140); // teal 绿
pub const POWER: Color32 = Color32::from_rgb(255, 194, 75); // 琥珀

// ---- 语义色 ----
pub const SUCCESS: Color32 = Color32::from_rgb(63, 214, 140);
pub const WARNING: Color32 = Color32::from_rgb(255, 194, 75);
pub const DANGER: Color32 = Color32::from_rgb(255, 107, 107);
pub const INFO: Color32 = Color32::from_rgb(76, 194, 255);
pub const GPU: Color32 = Color32::from_rgb(178, 143, 255); // 紫罗兰（GPU 专用）
pub const DANGER_FILL: Color32 = Color32::from_rgb(190, 55, 55); // 实心危险按钮底
pub const SELECT_BG: Color32 = Color32::from_rgb(31, 58, 77); // 选中行/选区

// ---- 控件底色 ----
const BTN_REST: Color32 = Color32::from_rgb(33, 38, 45);
const BTN_HOVER: Color32 = Color32::from_rgb(42, 49, 58);
const HANDLE_HOVER: Color32 = Color32::from_rgb(74, 85, 96);

/// 把主题应用到上下文：强制暗色，统一 Visuals / Spacing / 字体样式 / 滚动条。
pub fn apply(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    let visuals = visuals();
    ctx.all_styles_mut(move |s| {
        s.visuals = visuals.clone();
        s.spacing = spacing();
        s.text_styles = text_styles();
        s.animation_time = 0.15;
    });
}

fn widget(weak_bg: Color32, bg: Color32, stroke: Color32, fg: Color32, radius: u8) -> egui::style::WidgetVisuals {
    egui::style::WidgetVisuals {
        bg_fill: bg,
        weak_bg_fill: weak_bg,
        bg_stroke: Stroke::new(1.0, stroke),
        corner_radius: CornerRadius::same(radius),
        fg_stroke: Stroke::new(1.0, fg),
        expansion: 0.0,
    }
}

fn visuals() -> egui::Visuals {
    egui::Visuals {
        dark_mode: true,
        override_text_color: None,
        weak_text_color: Some(TEXT_MUTED),
        widgets: egui::style::Widgets {
            noninteractive: widget(SURFACE, SURFACE, BORDER, TEXT, 4),
            inactive: widget(BTN_REST, BORDER_STRONG, BORDER, TEXT, 6),
            hovered: widget(BTN_HOVER, HANDLE_HOVER, BORDER_STRONG, TEXT, 6),
            active: widget(SELECT_BG, CPU, CPU, TEXT, 6),
            open: widget(BTN_REST, BORDER_STRONG, BORDER, TEXT, 6),
        },
        selection: egui::style::Selection { bg_fill: SELECT_BG, stroke: Stroke::new(1.0, CPU) },
        hyperlink_color: CPU,
        faint_bg_color: FAINT,
        extreme_bg_color: EXTREME,
        text_edit_bg_color: Some(EXTREME),
        code_bg_color: ELEVATED,
        warn_fg_color: WARNING,
        error_fg_color: DANGER,
        window_corner_radius: CornerRadius::same(12),
        window_shadow: Shadow { offset: [0, 8], blur: 24, spread: 0, color: Color32::from_black_alpha(120) },
        window_fill: ELEVATED,
        window_stroke: Stroke::new(1.0, BORDER_STRONG),
        menu_corner_radius: CornerRadius::same(8),
        panel_fill: BG,
        popup_shadow: Shadow { offset: [0, 6], blur: 16, spread: 0, color: Color32::from_black_alpha(100) },
        striped: true,
        button_frame: true,
        collapsing_header_frame: false,
        slider_trailing_fill: true,
        disabled_alpha: 0.4,
        interact_cursor: Some(egui::CursorIcon::PointingHand),
        ..egui::Visuals::dark()
    }
}

fn spacing() -> egui::Spacing {
    egui::Spacing {
        item_spacing: Vec2::new(12.0, 10.0),
        window_margin: Margin::same(0),
        button_padding: Vec2::new(12.0, 6.0),
        interact_size: Vec2::new(40.0, 26.0),
        slider_width: 220.0,
        slider_rail_height: 6.0,
        text_edit_width: 240.0,
        indent: 16.0,
        // 自定义滚动条：细实条，轨道=EXTREME，滑块=widgets.bg_fill（随悬停/拖动变色）
        scroll: egui::style::ScrollStyle {
            floating: false,
            bar_width: 8.0,
            handle_min_length: 24.0,
            bar_inner_margin: 3.0,
            bar_outer_margin: 2.0,
            foreground_color: false,
            content_margin: Margin::ZERO,
            ..egui::style::ScrollStyle::solid()
        },
        ..egui::Spacing::default()
    }
}

fn text_styles() -> BTreeMap<egui::TextStyle, egui::FontId> {
    use egui::{FontFamily::Proportional, FontId, TextStyle};
    [
        (TextStyle::Small, FontId::new(11.0, Proportional)),
        (TextStyle::Body, FontId::new(13.5, Proportional)),
        (TextStyle::Button, FontId::new(13.5, Proportional)),
        (TextStyle::Heading, FontId::new(20.0, Proportional)),
        (TextStyle::Monospace, FontId::new(13.5, egui::FontFamily::Monospace)),
    ]
    .into()
}

/// 卡片外框：表面色 + 细边框 + 圆角 + 轻投影。
pub fn card_frame() -> egui::Frame {
    egui::Frame::NONE
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::same(14))
        .shadow(Shadow { offset: [0, 2], blur: 8, spread: 0, color: Color32::from_black_alpha(50) })
}

/// 把颜色向卡片表面色混合，amount=0 得表面色，1 得原色。用于徽章/按钮的淡色底。
pub fn tint(color: Color32, amount: f32) -> Color32 {
    let (r, g, b, _) = color.to_tuple();
    let (br, bg, bb, _) = SURFACE.to_tuple();
    let m = |c: u8, bc: u8| (bc as f32 + (c as f32 - bc as f32) * amount).round() as u8;
    Color32::from_rgb(m(r, br), m(g, bg), m(b, bb))
}

pub fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let (ar, ag, ab, _) = a.to_tuple();
    let (br, bg, bb, _) = b.to_tuple();
    let m = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(m(ar, br), m(ag, bg), m(ab, bb))
}

/// 负载热力色：空闲=弱文字、轻载=青、中载=琥珀、重载=红。用于 CPU/内存数值与进度条。
pub fn heat_color(frac: f32) -> Color32 {
    if frac >= 0.85 {
        DANGER
    } else if frac >= 0.60 {
        WARNING
    } else if frac >= 0.25 {
        CPU
    } else {
        TEXT_SEC
    }
}

/// 温度渐变：40°C 绿 → 70°C 琥珀 → 85°C 红。
pub fn temp_color(t: f32) -> Color32 {
    let f = ((t - 40.0) / 45.0).clamp(0.0, 1.0);
    if f < 0.5 {
        lerp_color(SUCCESS, WARNING, f / 0.5)
    } else {
        lerp_color(WARNING, DANGER, (f - 0.5) / 0.5)
    }
}

/// 进程状态 → (中文标签, 语义色)。徽章底色由 tint 生成。
pub fn state_badge(state: char) -> (&'static str, Color32) {
    match state {
        'R' => ("运行", SUCCESS),
        'S' => ("睡眠", TEXT_MUTED),
        'D' => ("等待", INFO),
        'I' => ("空闲", TEXT_MUTED),
        'T' => ("已停止", WARNING),
        't' => ("跟踪", WARNING),
        'Z' => ("僵尸", DANGER),
        'X' | 'x' => ("退出", TEXT_MUTED),
        _ => ("其他", TEXT_SEC),
    }
}