use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct Config {
    pub enabled: bool,
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
            temp_high: 80.0,
            temp_low: 70.0,
            cpu_high: 90.0,
            throttle_pct: 50,
            target_group: None,
            cooldown_secs: 20,
        }
    }
}

#[derive(Clone, Copy)]
pub struct Snapshot {
    pub temp_c: Option<f32>,
    pub cpu_percent: f32,
    pub throttled: bool,
    pub undervoltage: bool,
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

/// 纯函数策略评估：依据当前状态与快照决定建议动作，无任何副作用。
/// 状态迁移由调用方在动作执行成功后经 [`State::commit`] 完成。
pub fn evaluate(cfg: &Config, snap: &Snapshot, st: &State, now: Instant) -> Vec<Action> {
    if !cfg.enabled || st.halted || st.in_backoff(now) {
        return vec![];
    }
    let Some(group) = cfg.target_group.clone() else {
        return vec![];
    };
    let cooled = st
        .last_change
        .is_none_or(|t| now.duration_since(t) >= Duration::from_secs(cfg.cooldown_secs));
    let hot = snap.temp_c.is_some_and(|t| t >= cfg.temp_high)
        || snap.cpu_percent >= cfg.cpu_high
        || snap.throttled
        || snap.undervoltage;
    let cool = snap.temp_c.is_some_and(|t| t <= cfg.temp_low)
        && snap.cpu_percent < cfg.cpu_high
        && !snap.throttled
        && !snap.undervoltage;

    if !st.engaged && hot && cooled {
        vec![Action::Engage { group, pct: cfg.throttle_pct }]
    } else if st.engaged && cool && cooled {
        vec![Action::Restore { group }]
    } else {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_on() -> Config {
        Config { enabled: true, target_group: Some("g".into()), ..Config::default() }
    }

    fn hot_snap() -> Snapshot {
        Snapshot { temp_c: Some(95.0), cpu_percent: 0.0, throttled: false, undervoltage: false }
    }

    fn cool_snap() -> Snapshot {
        Snapshot { temp_c: Some(60.0), cpu_percent: 0.0, throttled: false, undervoltage: false }
    }

    #[test]
    fn engages_on_high_cpu() {
        let st = State::default();
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(50.0), cpu_percent: 95.0, throttled: false, undervoltage: false };
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
        let s = Snapshot { temp_c: Some(99.0), throttled: true, undervoltage: true, cpu_percent: 0.0 };
        assert!(evaluate(&c, &s, &st, Instant::now()).is_empty());
    }

    #[test]
    fn no_target_group_does_nothing() {
        let st = State::default();
        let c = Config { enabled: true, target_group: None, ..Config::default() };
        let s = Snapshot { temp_c: Some(99.0), throttled: false, undervoltage: false, cpu_percent: 0.0 };
        assert!(evaluate(&c, &s, &st, Instant::now()).is_empty());
    }

    #[test]
    fn engages_on_high_temp() {
        let st = State::default();
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(85.0), throttled: false, undervoltage: false, cpu_percent: 0.0 };
        assert_eq!(evaluate(&c, &s, &st, Instant::now()), vec![Action::Engage { group: "g".into(), pct: 50 }]);
    }

    #[test]
    fn engages_on_throttle_even_if_cool() {
        let st = State::default();
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(50.0), throttled: true, undervoltage: false, cpu_percent: 0.0 };
        assert_eq!(evaluate(&c, &s, &st, Instant::now()), vec![Action::Engage { group: "g".into(), pct: 50 }]);
    }

    #[test]
    fn stays_engaged_in_hysteresis_band() {
        let st = State { engaged: true, last_change: None, ..State::default() };
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(75.0), throttled: false, undervoltage: false, cpu_percent: 0.0 };
        assert!(evaluate(&c, &s, &st, Instant::now()).is_empty());
    }

    #[test]
    fn releases_when_cool() {
        let base = Instant::now();
        let st = State { engaged: true, last_change: Some(base), ..State::default() };
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(68.0), throttled: false, undervoltage: false, cpu_percent: 0.0 };
        assert_eq!(evaluate(&c, &s, &st, base + Duration::from_secs(21)), vec![Action::Restore { group: "g".into() }]);
    }

    #[test]
    fn cooldown_blocks_release() {
        let base = Instant::now();
        let st = State { engaged: true, last_change: Some(base), ..State::default() };
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(60.0), throttled: false, undervoltage: false, cpu_percent: 0.0 };
        assert!(evaluate(&c, &s, &st, base + Duration::from_secs(5)).is_empty());
    }

    #[test]
    fn cooldown_blocks_re_engage() {
        let base = Instant::now();
        let st = State { engaged: false, last_change: Some(base), ..State::default() };
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(90.0), throttled: false, undervoltage: false, cpu_percent: 0.0 };
        assert!(evaluate(&c, &s, &st, base + Duration::from_secs(3)).is_empty());
    }

    #[test]
    fn none_temp_does_not_release() {
        let st = State { engaged: true, last_change: None, ..State::default() };
        let c = cfg_on();
        let s = Snapshot { temp_c: None, throttled: false, undervoltage: false, cpu_percent: 0.0 };
        assert!(evaluate(&c, &s, &st, Instant::now()).is_empty());
    }
}
