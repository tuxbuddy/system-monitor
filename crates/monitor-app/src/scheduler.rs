use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct Config {
    pub enabled: bool,
    pub mode: Mode,
    /// PSI cpu some 触发阈值（avg10 百分比）。
    pub psi_cpu_threshold: f32,
    /// PSI io some 触发阈值。
    pub psi_io_threshold: f32,
    pub temp_high: f32,
    pub temp_low: f32,
    pub cpu_high: f32,
    pub throttle_pct: u32,
    pub target_group: Option<String>,
    pub cooldown_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: Mode::Recommend,
            psi_cpu_threshold: 40.0,
            psi_io_threshold: 50.0,
            temp_high: 80.0,
            temp_low: 70.0,
            cpu_high: 90.0,
            throttle_pct: 50,
            target_group: None,
            cooldown_secs: 20,
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct Snapshot {
    pub temp_c: Option<f32>,
    pub cpu_percent: f32,
    pub throttled: bool,
    pub undervoltage: bool,
    /// PSI cpu some avg10（0-100）；内核未启用 PSI 为 None。
    pub psi_cpu_some10: Option<f32>,
    /// PSI io some avg10。
    pub psi_io_some10: Option<f32>,
}

/// 运行模式（#28）：默认 recommend（只建议不执行）；auto 需显式开启。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Mode {
    /// 只产出建议（Decision），不自动执行动作。
    #[default]
    Recommend,
    /// 自动执行（仍只允许 L2 可恢复动作）。
    Auto,
}

#[derive(Clone, PartialEq, Debug)]
pub enum Action {
    Engage { group: String, pct: u32 },
    Restore { group: String },
}

/// 连续失败达到该次数后熔断：停止自动动作并进入告警，直到人工重新启用。
pub const MAX_CONSECUTIVE_FAILURES: u32 = 5;

/// 自动调度状态机。
///
/// 不变量：`engaged` / `last_change` 只在执行器确认写成功后由 [`State::commit`]
/// 迁移；[`evaluate`] 是纯函数，不修改状态。写入失败时保持原状态并进入指数
/// 退避重试，连续失败 [`MAX_CONSECUTIVE_FAILURES`] 次后 `halted` 熔断。
#[derive(Default, Clone)]
pub struct State {
    pub engaged: bool,
    pub last_change: Option<Instant>,
    consecutive_failures: u32,
    backoff_until: Option<Instant>,
    pub halted: bool,
}

impl State {
    /// 执行器回调：`ok` 表示 cgroup 写入成功。成功才迁移状态并重置失败计数；
    /// 失败保持原状态、累计失败并按 2^n 秒退避。
    pub fn commit(&mut self, action: &Action, ok: bool, now: Instant) {
        if ok {
            self.engaged = matches!(action, Action::Engage { .. });
            self.last_change = Some(now);
            self.consecutive_failures = 0;
            self.backoff_until = None;
            return;
        }
        self.consecutive_failures += 1;
        let backoff_secs = 1u64 << self.consecutive_failures.min(6);
        self.backoff_until = Some(now + Duration::from_secs(backoff_secs));
        if self.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
            self.halted = true;
        }
    }

    /// 熔断后人工重新启用（或条件解除由调用方决定）时清零。
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    fn in_backoff(&self, now: Instant) -> bool {
        self.backoff_until.is_some_and(|t| now < t)
    }
}

/// 可解释决策（#28）：每个动作携带触发信号与阈值,前端/会话直接展示。
#[derive(Clone, PartialEq, Debug)]
pub struct Decision {
    pub action: Action,
    /// 触发证据：形如 "cpu 95.0% ≥ 90.0%" / "psi.cpu.some(avg10) 45.2 ≥ 40.0"。
    pub reasons: Vec<String>,
    /// 证据条数（≥2 视为高置信；单信号为 medium）。
    pub confidence: Confidence,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Confidence {
    /// 2+ 个独立信号同时触发。
    High,
    /// 单信号触发。
    Medium,
}

/// 纯函数策略评估 v2：多信号输入 + 可解释决策。
/// 旧 evaluate 保留为薄包装（兼容既有调用与测试）。
pub fn evaluate(cfg: &Config, snap: &Snapshot, st: &State, now: Instant) -> Vec<Action> {
    evaluate_v2(cfg, snap, st, now).into_iter().map(|d| d.action).collect()
}

/// 推荐模式入口：只产出建议，调用方（GUI/MCP）展示,不自动执行。
pub fn recommend(cfg: &Config, snap: &Snapshot, st: &State, now: Instant) -> Vec<Decision> {
    evaluate_v2(cfg, snap, st, now)
}

fn evaluate_v2(cfg: &Config, snap: &Snapshot, st: &State, now: Instant) -> Vec<Decision> {
    if !cfg.enabled || st.halted || st.in_backoff(now) {
        return vec![];
    }
    let Some(group) = cfg.target_group.clone() else {
        return vec![];
    };
    let cooled = st
        .last_change
        .is_none_or(|t| now.duration_since(t) >= Duration::from_secs(cfg.cooldown_secs));

    // 多信号收集：CPU 高不一定异常——PSI 正常时降权处理（防止误限流编译机）
    let mut engage_reasons = Vec::new();
    if snap.temp_c.is_some_and(|t| t >= cfg.temp_high) {
        engage_reasons.push(format!("temp {:.1}°C ≥ {:.1}°C", snap.temp_c.unwrap(), cfg.temp_high));
    }
    if snap.cpu_percent >= cfg.cpu_high {
        engage_reasons.push(format!("cpu {:.1}% ≥ {:.1}%", snap.cpu_percent, cfg.cpu_high));
    }
    if snap.psi_cpu_some10.is_some_and(|v| v >= cfg.psi_cpu_threshold) {
        engage_reasons.push(format!(
            "psi.cpu.some(avg10) {:.1} ≥ {:.1}",
            snap.psi_cpu_some10.unwrap(),
            cfg.psi_cpu_threshold
        ));
    }
    if snap.psi_io_some10.is_some_and(|v| v >= cfg.psi_io_threshold) {
        engage_reasons.push(format!(
            "psi.io.some(avg10) {:.1} ≥ {:.1}",
            snap.psi_io_some10.unwrap(),
            cfg.psi_io_threshold
        ));
    }
    if snap.throttled {
        engage_reasons.push("硬件已频率受限(throttled)".to_string());
    }
    if snap.undervoltage {
        engage_reasons.push("欠压(undervoltage)".to_string());
    }

    let cool = snap.temp_c.is_some_and(|t| t <= cfg.temp_low)
        && snap.cpu_percent < cfg.cpu_high
        && !snap.throttled
        && !snap.undervoltage
        && !snap.psi_cpu_some10.is_some_and(|v| v >= cfg.psi_cpu_threshold);

    if !st.engaged && cooled && !engage_reasons.is_empty() {
        // 误限流防线：仅 cpu 高但 PSI 正常 → 降级为单信号(medium),且要求
        // cpu 超阈值更多才触发（滞回余量 5%）
        if engage_reasons.len() == 1
            && engage_reasons[0].starts_with("cpu ")
            && snap.psi_cpu_some10.is_none_or(|v| v < cfg.psi_cpu_threshold)
            && snap.cpu_percent < cfg.cpu_high + 5.0
        {
            return vec![];
        }
        let confidence = if engage_reasons.len() >= 2 { Confidence::High } else { Confidence::Medium };
        return vec![Decision {
            action: Action::Engage { group, pct: cfg.throttle_pct },
            reasons: engage_reasons,
            confidence,
        }];
    }
    if st.engaged && cooled && cool {
        return vec![Decision {
            action: Action::Restore { group },
            reasons: vec!["全部信号回落至恢复带".to_string()],
            confidence: Confidence::High,
        }];
    }
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_on() -> Config {
        Config { enabled: true, target_group: Some("g".into()), ..Config::default() }
    }

    fn hot_snap() -> Snapshot {
        Snapshot { psi_cpu_some10: None, psi_io_some10: None, temp_c: Some(95.0), cpu_percent: 0.0, throttled: false, undervoltage: false }
    }

    fn cool_snap() -> Snapshot {
        Snapshot { psi_cpu_some10: None, psi_io_some10: None, temp_c: Some(60.0), cpu_percent: 0.0, throttled: false, undervoltage: false }
    }

    #[test]
    fn engages_on_high_cpu() {
        let st = State::default();
        let c = cfg_on();
        let s = Snapshot { psi_cpu_some10: None, psi_io_some10: None, temp_c: Some(50.0), cpu_percent: 95.0, throttled: false, undervoltage: false };
        assert_eq!(evaluate(&c, &s, &st, Instant::now()), vec![Action::Engage { group: "g".into(), pct: 50 }]);
    }

    #[test]
    fn evaluate_is_pure_until_commit() {
        // 纯函数：同输入重复调用结果一致，且不修改状态
        let mut st = State::default();
        let c = cfg_on();
        let a1 = evaluate(&c, &hot_snap(), &st, Instant::now());
        let a2 = evaluate(&c, &hot_snap(), &st, Instant::now());
        assert_eq!(a1, a2);
        assert!(!st.engaged, "evaluate 不得修改状态");
        // 执行失败：状态保持未限流
        let now = Instant::now();
        st.commit(&a1[0], false, now);
        assert!(!st.engaged, "写入失败不得提交 engaged");
        assert_eq!(st.last_change, None);
        assert_eq!(st.consecutive_failures(), 1);
    }

    #[test]
    fn failed_engage_retries_after_backoff() {
        let mut st = State::default();
        let c = cfg_on();
        let now = Instant::now();
        let a = evaluate(&c, &hot_snap(), &st, now);
        st.commit(&a[0], false, now);
        // 退避期内不再触发（2^1=2s）
        assert!(evaluate(&c, &hot_snap(), &st, now + Duration::from_secs(1)).is_empty());
        // 退避过后重试同一动作
        let later = now + Duration::from_secs(3);
        assert_eq!(
            evaluate(&c, &hot_snap(), &st, later),
            vec![Action::Engage { group: "g".into(), pct: 50 }],
            "失败后应保持原状态并重试"
        );
        // 这次成功：状态提交
        st.commit(&a[0], true, later);
        assert!(st.engaged);
        assert_eq!(st.last_change, Some(later), "last_change 只在成功后更新");
    }

    #[test]
    fn consecutive_failures_halt_auto_actions() {
        let mut st = State::default();
        let c = cfg_on();
        let mut now = Instant::now();
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            let a = evaluate(&c, &hot_snap(), &st, now);
            assert!(!a.is_empty(), "退避解除后应有动作");
            st.commit(&a[0], false, now);
            now += Duration::from_secs(120); // 跳过所有退避窗口
        }
        assert!(st.halted, "连续失败 {} 次应熔断", MAX_CONSECUTIVE_FAILURES);
        assert!(evaluate(&c, &hot_snap(), &st, now + Duration::from_secs(600)).is_empty(), "熔断后不再自动动作");
        // 人工 reset 后恢复
        st.reset();
        assert!(!st.halted);
        assert!(!evaluate(&c, &hot_snap(), &st, now + Duration::from_secs(600)).is_empty());
    }

    #[test]
    fn restore_commits_only_on_success() {
        let mut st = State { engaged: true, ..State::default() };
        let c = cfg_on();
        let now = Instant::now();
        st.last_change = Some(now);
        let a = evaluate(&c, &cool_snap(), &st, now + Duration::from_secs(21));
        assert_eq!(a, vec![Action::Restore { group: "g".into() }]);
        // 解除限流失败：仍处于 engaged，稍后重试
        st.commit(&a[0], false, now + Duration::from_secs(21));
        assert!(st.engaged, "Restore 写失败不得提交");
        // 成功后解除
        let later = now + Duration::from_secs(40);
        let a2 = evaluate(&c, &cool_snap(), &st, later);
        assert_eq!(a2, vec![Action::Restore { group: "g".into() }], "应重试 Restore");
        st.commit(&a2[0], true, later);
        assert!(!st.engaged);
    }

    #[test]
    fn disabled_does_nothing() {
        let st = State::default();
        let c = Config { enabled: false, target_group: Some("g".into()), ..Config::default() };
        let s = Snapshot { psi_cpu_some10: None, psi_io_some10: None, temp_c: Some(99.0), throttled: true, undervoltage: true, cpu_percent: 0.0 };
        assert!(evaluate(&c, &s, &st, Instant::now()).is_empty());
    }

    #[test]
    fn no_target_group_does_nothing() {
        let st = State::default();
        let c = Config { enabled: true, target_group: None, ..Config::default() };
        let s = Snapshot { psi_cpu_some10: None, psi_io_some10: None, temp_c: Some(99.0), throttled: false, undervoltage: false, cpu_percent: 0.0 };
        assert!(evaluate(&c, &s, &st, Instant::now()).is_empty());
    }

    #[test]
    fn engages_on_high_temp() {
        let st = State::default();
        let c = cfg_on();
        let s = Snapshot { psi_cpu_some10: None, psi_io_some10: None, temp_c: Some(85.0), throttled: false, undervoltage: false, cpu_percent: 0.0 };
        assert_eq!(evaluate(&c, &s, &st, Instant::now()), vec![Action::Engage { group: "g".into(), pct: 50 }]);
    }

    #[test]
    fn engages_on_throttle_even_if_cool() {
        let st = State::default();
        let c = cfg_on();
        let s = Snapshot { psi_cpu_some10: None, psi_io_some10: None, temp_c: Some(50.0), throttled: true, undervoltage: false, cpu_percent: 0.0 };
        assert_eq!(evaluate(&c, &s, &st, Instant::now()), vec![Action::Engage { group: "g".into(), pct: 50 }]);
    }

    #[test]
    fn stays_engaged_in_hysteresis_band() {
        let st = State { engaged: true, last_change: None, ..State::default() };
        let c = cfg_on();
        let s = Snapshot { psi_cpu_some10: None, psi_io_some10: None, temp_c: Some(75.0), throttled: false, undervoltage: false, cpu_percent: 0.0 };
        assert!(evaluate(&c, &s, &st, Instant::now()).is_empty());
    }

    #[test]
    fn releases_when_cool() {
        let base = Instant::now();
        let st = State { engaged: true, last_change: Some(base), ..State::default() };
        let c = cfg_on();
        let s = Snapshot { psi_cpu_some10: None, psi_io_some10: None, temp_c: Some(68.0), throttled: false, undervoltage: false, cpu_percent: 0.0 };
        assert_eq!(evaluate(&c, &s, &st, base + Duration::from_secs(21)), vec![Action::Restore { group: "g".into() }]);
    }

    #[test]
    fn cooldown_blocks_release() {
        let base = Instant::now();
        let st = State { engaged: true, last_change: Some(base), ..State::default() };
        let c = cfg_on();
        let s = Snapshot { psi_cpu_some10: None, psi_io_some10: None, temp_c: Some(60.0), throttled: false, undervoltage: false, cpu_percent: 0.0 };
        assert!(evaluate(&c, &s, &st, base + Duration::from_secs(5)).is_empty());
    }

    #[test]
    fn cooldown_blocks_re_engage() {
        let base = Instant::now();
        let st = State { engaged: false, last_change: Some(base), ..State::default() };
        let c = cfg_on();
        let s = Snapshot { psi_cpu_some10: None, psi_io_some10: None, temp_c: Some(90.0), throttled: false, undervoltage: false, cpu_percent: 0.0 };
        assert!(evaluate(&c, &s, &st, base + Duration::from_secs(3)).is_empty());
    }

    #[test]
    fn none_temp_does_not_release() {
        let st = State { engaged: true, last_change: None, ..State::default() };
        let c = cfg_on();
        let s = Snapshot { psi_cpu_some10: None, psi_io_some10: None, temp_c: None, throttled: false, undervoltage: false, cpu_percent: 0.0 };
        assert!(evaluate(&c, &s, &st, Instant::now()).is_empty());
    }

    // ---- v2 仿真（#28）----

    fn cfg_auto() -> Config {
        Config { enabled: true, mode: Mode::Auto, target_group: Some("g".into()), ..Config::default() }
    }

    fn snap(cpu: f32, psi_cpu: Option<f32>, psi_io: Option<f32>, temp: Option<f32>) -> Snapshot {
        Snapshot { temp_c: temp, cpu_percent: cpu, throttled: false, undervoltage: false, psi_cpu_some10: psi_cpu, psi_io_some10: psi_io }
    }

    #[test]
    fn high_cpu_with_normal_psi_is_dampened() {
        // 高 CPU 但 PSI 正常:编译机常态,不应误限流
        let st = State::default();
        let c = cfg_auto();
        assert!(evaluate_v2(&c, &snap(91.0, Some(8.0), Some(3.0), None), &st, Instant::now()).is_empty());
        // cpu 超出阈值+滞回余量才触发(单信号 medium)
        let d = evaluate_v2(&c, &snap(96.0, Some(8.0), Some(3.0), None), &st, Instant::now());
        assert!(matches!(d[0].confidence, Confidence::Medium));
    }

    #[test]
    fn high_cpu_with_psi_pressure_is_high_confidence() {
        let st = State::default();
        let c = cfg_auto();
        let d = evaluate_v2(&c, &snap(95.0, Some(45.0), Some(3.0), None), &st, Instant::now());
        assert!(!d.is_empty());
        assert!(matches!(d[0].confidence, Confidence::High), "双信号应高置信：{d:?}");
        assert_eq!(d[0].reasons.len(), 2);
        assert!(d[0].reasons.iter().any(|r| r.contains("psi.cpu")));
    }

    #[test]
    fn io_pressure_alone_triggers_medium() {
        let st = State::default();
        let c = cfg_auto();
        let d = evaluate_v2(&c, &snap(10.0, Some(2.0), Some(60.0), None), &st, Instant::now());
        assert!(!d.is_empty());
        assert!(d[0].reasons.iter().any(|r| r.contains("psi.io")));
    }

    #[test]
    fn oscillation_is_dampened_by_cooldown_and_hysteresis() {
        let mut st = State::default();
        let c = cfg_auto();
        let mut now = Instant::now();
        // 触发
        let d = evaluate_v2(&c, &snap(95.0, Some(45.0), None, Some(85.0)), &st, now);
        assert_eq!(d.len(), 1);
        st.commit(&d[0].action, true, now);
        // 冷却期内即使指标来回摆动也不动作
        for i in 0..4 {
            now += Duration::from_secs(4);
            let s = if i % 2 == 0 { snap(20.0, Some(1.0), None, Some(65.0)) } else { snap(99.0, Some(90.0), None, Some(95.0)) };
            assert!(evaluate_v2(&c, &s, &st, now).is_empty(), "冷却期内不得抖动");
        }
        // 冷却结束且全部回落 → 恢复
        now += Duration::from_secs(30);
        let d = evaluate_v2(&c, &snap(20.0, Some(1.0), None, Some(65.0)), &st, now);
        assert_eq!(d.len(), 1);
        assert!(matches!(d[0].action, Action::Restore { .. }));
    }

    #[test]
    fn recommend_mode_returns_decisions_without_state_mutation() {
        let st = State::default();
        let mut c = cfg_auto();
        c.mode = Mode::Recommend;
        let d = recommend(&c, &snap(95.0, Some(45.0), None, Some(85.0)), &st, Instant::now());
        assert_eq!(d.len(), 1);
        assert!(!st.engaged, "recommend 不改状态");
        assert!(!d[0].reasons.is_empty(), "决策必须可解释");
    }
}
