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

#[derive(Default)]
pub struct State {
    pub engaged: bool,
    pub last_change: Option<Instant>,
}

pub fn evaluate(cfg: &Config, snap: &Snapshot, st: &mut State, now: Instant) -> Vec<Action> {
    if !cfg.enabled {
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
        st.engaged = true;
        st.last_change = Some(now);
        vec![Action::Engage { group, pct: cfg.throttle_pct }]
    } else if st.engaged && cool && cooled {
        st.engaged = false;
        st.last_change = Some(now);
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

    #[test]
    fn engages_on_high_cpu() {
        let mut st = State::default();
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(50.0), cpu_percent: 95.0, throttled: false, undervoltage: false };
        let a = evaluate(&c, &s, &mut st, Instant::now());
        assert_eq!(a, vec![Action::Engage { group: "g".into(), pct: 50 }]);
        assert!(st.engaged);
    }

    #[test]
    fn disabled_does_nothing() {
        let mut st = State::default();
        let c = Config { enabled: false, target_group: Some("g".into()), ..Config::default() };
        let s = Snapshot { temp_c: Some(99.0), throttled: true, undervoltage: true, cpu_percent: 0.0 };
        assert!(evaluate(&c, &s, &mut st, Instant::now()).is_empty());
        assert!(!st.engaged);
    }

    #[test]
    fn no_target_group_does_nothing() {
        let mut st = State::default();
        let c = Config { enabled: true, target_group: None, ..Config::default() };
        let s = Snapshot { temp_c: Some(99.0), throttled: false, undervoltage: false, cpu_percent: 0.0 };
        assert!(evaluate(&c, &s, &mut st, Instant::now()).is_empty());
    }

    #[test]
    fn engages_on_high_temp() {
        let mut st = State::default();
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(85.0), throttled: false, undervoltage: false, cpu_percent: 0.0 };
        let a = evaluate(&c, &s, &mut st, Instant::now());
        assert_eq!(a, vec![Action::Engage { group: "g".into(), pct: 50 }]);
        assert!(st.engaged);
    }

    #[test]
    fn engages_on_throttle_even_if_cool() {
        let mut st = State::default();
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(50.0), throttled: true, undervoltage: false, cpu_percent: 0.0 };
        let a = evaluate(&c, &s, &mut st, Instant::now());
        assert_eq!(a, vec![Action::Engage { group: "g".into(), pct: 50 }]);
    }

    #[test]
    fn stays_engaged_in_hysteresis_band() {
        let mut st = State { engaged: true, last_change: None };
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(75.0), throttled: false, undervoltage: false, cpu_percent: 0.0 };
        assert!(evaluate(&c, &s, &mut st, Instant::now()).is_empty());
        assert!(st.engaged);
    }

    #[test]
    fn releases_when_cool() {
        let base = Instant::now();
        let mut st = State { engaged: true, last_change: Some(base) };
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(68.0), throttled: false, undervoltage: false, cpu_percent: 0.0 };
        let a = evaluate(&c, &s, &mut st, base + Duration::from_secs(21));
        assert_eq!(a, vec![Action::Restore { group: "g".into() }]);
        assert!(!st.engaged);
    }

    #[test]
    fn cooldown_blocks_release() {
        let base = Instant::now();
        let mut st = State { engaged: true, last_change: Some(base) };
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(60.0), throttled: false, undervoltage: false, cpu_percent: 0.0 };
        assert!(evaluate(&c, &s, &mut st, base + Duration::from_secs(5)).is_empty());
        assert!(st.engaged);
    }

    #[test]
    fn cooldown_blocks_re_engage() {
        let base = Instant::now();
        let mut st = State { engaged: false, last_change: Some(base) };
        let c = cfg_on();
        let s = Snapshot { temp_c: Some(90.0), throttled: false, undervoltage: false, cpu_percent: 0.0 };
        assert!(evaluate(&c, &s, &mut st, base + Duration::from_secs(3)).is_empty());
        assert!(!st.engaged);
    }

    #[test]
    fn none_temp_does_not_release() {
        let mut st = State { engaged: true, last_change: None };
        let c = cfg_on();
        let s = Snapshot { temp_c: None, throttled: false, undervoltage: false, cpu_percent: 0.0 };
        assert!(evaluate(&c, &s, &mut st, Instant::now()).is_empty());
        assert!(st.engaged);
    }
}