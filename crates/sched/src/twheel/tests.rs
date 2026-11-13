use super::*;
use std::any::Any;
use std::cell::{Cell, RefCell};

thread_local! {
    static CLOCK: Cell<i64> = const { Cell::new(0) };
    static FIRED: RefCell<Vec<(usize, i64)>> = const { RefCell::new(Vec::new()) };
    static NOW: Cell<i64> = const { Cell::new(0) };
    static CANCEL_TARGET: Cell<Option<Pin<&'static TWheelTimer>>> = const { Cell::new(None) };
    static SET_TARGET: Cell<Option<Pin<&'static TWheelTimer>>> = const { Cell::new(None) };
}

fn clock() -> i64 {
    CLOCK.with(Cell::get)
}

fn record(_wheel: &mut TimerWheel, _esdp: &mut dyn Any, arg: *mut ()) {
    let now = NOW.with(Cell::get);
    FIRED.with(|f| f.borrow_mut().push((arg.addr(), now)));
}

/// A timer argument that only carries a number.
fn id(n: usize) -> *mut () {
    std::ptr::without_provenance_mut(n)
}

fn take_fired() -> Vec<(usize, i64)> {
    FIRED.with(|f| std::mem::take(&mut *f.borrow_mut()))
}

fn wheel_at(pos: i64) -> TimerWheel {
    CLOCK.with(|c| c.set(pos));
    NOW.with(|c| c.set(pos));
    take_fired();
    TimerWheel::new(clock())
}

/// Bumps to `to` until the bump no longer yields; returns the number of bump calls.
fn bump_to(wheel: &mut TimerWheel, to: i64) -> usize {
    NOW.with(|c| c.set(to));
    let mut calls = 0;
    loop {
        wheel.bump_timers(to, &mut ());
        calls += 1;
        if wheel.yield_slot == SLOT_INACTIVE {
            return calls;
        }
    }
}

fn timers(n: usize) -> Vec<Pin<Box<TWheelTimer>>> {
    (0..n).map(|_| Box::pin(TWheelTimer::new())).collect()
}

/// xorshift64*, deterministic.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
fn every_timer_fires_at_its_position_when_bumped_each_tick() {
    let positions: Vec<i64> = vec![
        999,
        1000,
        1001,
        1002,
        1000 + 4095,
        1000 + 4096,
        1000 + 8191,
        1000 + i64::from(SOON_WHEEL_SIZE) - 1,
        1000 + i64::from(SOON_WHEEL_SIZE),
        1000 + i64::from(SOON_WHEEL_SIZE) + 1,
        1000 + 3 * LATER_WHEEL_SLOT_SIZE + 17,
        1000 + 5 * i64::from(SOON_WHEEL_SIZE) + 3,
    ];
    let ts = timers(positions.len());
    let mut wheel = wheel_at(1000);
    for (i, (t, pos)) in ts.iter().zip(&positions).enumerate() {
        wheel.set_timer(t.as_ref(), record, id(i), *pos);
    }
    let end = 1000 + 6 * i64::from(SOON_WHEEL_SIZE);
    for now in 1001..=end {
        bump_to(&mut wheel, now);
    }
    let mut fired = take_fired();
    fired.sort();
    let expected: Vec<(usize, i64)> = positions
        .iter()
        .enumerate()
        .map(|(i, pos)| (i, (*pos).max(1001)))
        .collect();
    assert_eq!(fired, expected);
    assert!(ts.iter().all(|t| !t.is_active()));
    assert_eq!(wheel.nto, 0);
}

#[test]
fn random_set_cancel_and_jumps_match_a_model() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let start = 50_000;
    let n = 3000;
    let ts = timers(n);
    let mut wheel = wheel_at(start);
    let mut deadline: Vec<Option<i64>> = vec![None; n];
    let mut now = start;
    let mut total_fired = 0;
    for _ in 0..20_000 {
        match rng.below(10) {
            0..=5 => {
                let i = rng.below(n as u64) as usize;
                if !ts[i].is_active() {
                    let range = match rng.below(4) {
                        0 => 50,
                        1 => i64::from(SOON_WHEEL_SIZE),
                        2 => 4 * i64::from(SOON_WHEEL_SIZE),
                        _ => TIMER_WHEEL_MSEC,
                    };
                    let pos = now - 5 + rng.below(range as u64) as i64;
                    wheel.set_timer(ts[i].as_ref(), record, id(i), pos);
                    deadline[i] = Some(pos);
                }
            }
            6 => {
                let i = rng.below(n as u64) as usize;
                wheel.cancel_timer(ts[i].as_ref());
                deadline[i] = None;
            }
            _ => {
                let step = match rng.below(5) {
                    0 => 1,
                    1 => rng.below(100) as i64,
                    2 => rng.below(i64::from(SOON_WHEEL_SIZE) as u64) as i64,
                    3 => rng.below((8 * i64::from(SOON_WHEEL_SIZE)) as u64) as i64,
                    _ => 0,
                };
                now += step;
                bump_to(&mut wheel, now);
                for (i, at) in take_fired() {
                    total_fired += 1;
                    let pos = deadline[i].take().expect("fired timer was set");
                    assert!(pos <= at, "timer {i} at {pos} fired early at {at}");
                    assert_eq!(at, now);
                }
                for (i, d) in deadline.iter().enumerate() {
                    if let Some(pos) = d {
                        assert!(*pos > now, "timer {i} at {pos} not fired by {now}");
                        assert!(ts[i].is_active());
                    }
                }
                let next = wheel.check_next_timeout_time(clock);
                let min = deadline.iter().flatten().min().copied();
                if let Some(min) = min {
                    assert!(next <= min, "next timeout {next} after earliest {min}");
                }
            }
        }
        assert_eq!(wheel.nto, deadline.iter().flatten().count());
    }
    assert!(total_fired > 2000, "only {total_fired} timers fired");
}

#[test]
fn next_timeout_is_exact_in_the_soon_wheel_and_early_for_the_later_wheel() {
    let ts = timers(2);
    let mut wheel = wheel_at(0);
    assert_eq!(wheel.check_next_timeout_time(clock), CLKTCKS_WEEK);
    let later = 3 * i64::from(SOON_WHEEL_SIZE) + 77;
    wheel.set_timer(ts[0].as_ref(), record, id(0), later);
    let pre = wheel.check_next_timeout_time(clock);
    assert_eq!(pre, (later & LATER_WHEEL_POS_MASK) - LATER_WHEEL_SLOT_SIZE);
    wheel.set_timer(ts[1].as_ref(), record, id(1), 1234);
    assert_eq!(wheel.check_next_timeout_time(clock), 1234);
    wheel.cancel_timer(ts[1].as_ref());
    assert!(wheel.check_next_timeout_time(clock) <= later);
    wheel.cancel_timer(ts[0].as_ref());
    assert_eq!(wheel.nto, 0);
}

#[test]
fn bump_yields_after_the_limit_and_resumes_in_the_same_slot() {
    let n = 250;
    let ts = timers(n);
    let mut wheel = wheel_at(0);
    for (i, t) in ts.iter().enumerate() {
        wheel.set_timer(t.as_ref(), record, id(i), 10);
    }
    NOW.with(|c| c.set(10));
    wheel.bump_timers(10, &mut ());
    let first = take_fired().len();
    assert!(first < n, "first bump fired all {first}");
    assert_ne!(wheel.yield_slot, SLOT_INACTIVE);
    let calls = bump_to(&mut wheel, 10);
    assert!(calls >= 2);
    assert_eq!(first + take_fired().len(), n);
}

fn set_at_once(wheel: &mut TimerWheel, esdp: &mut dyn Any, arg: *mut ()) {
    record(wheel, esdp, arg);
    let target = SET_TARGET.with(Cell::take).expect("target");
    let pos = NOW.with(Cell::get);
    wheel.set_timer(target, record, id(100), pos);
}

fn cancel_other(wheel: &mut TimerWheel, esdp: &mut dyn Any, arg: *mut ()) {
    record(wheel, esdp, arg);
    if let Some(target) = CANCEL_TARGET.with(Cell::take) {
        wheel.cancel_timer(target);
    }
}

#[test]
fn callbacks_may_set_and_cancel_timers_on_the_bumping_wheel() {
    let a = Box::pin(TWheelTimer::new());
    let b: Pin<&'static TWheelTimer> = Pin::static_ref(Box::leak(Box::new(TWheelTimer::new())));
    let c: Pin<&'static TWheelTimer> = Pin::static_ref(Box::leak(Box::new(TWheelTimer::new())));
    let d = Box::pin(TWheelTimer::new());
    let mut wheel = wheel_at(0);
    // `a` and `c` share a slot: `a` fires first and cancels `c` while it sits on the sentinel.
    wheel.set_timer(a.as_ref(), cancel_other, id(1), 5);
    wheel.set_timer(c, record, id(3), 5);
    // `d` sets `b` at once from its callback.
    wheel.set_timer(d.as_ref(), set_at_once, id(4), 7);
    CANCEL_TARGET.with(|t| t.set(Some(c)));
    SET_TARGET.with(|t| t.set(Some(b)));
    bump_to(&mut wheel, 10);
    let fired = take_fired();
    assert_eq!(fired, vec![(1, 10), (4, 10), (100, 10)]);
    assert!(!c.is_active() && !b.is_active());
    assert_eq!(wheel.nto, 0);
}

#[test]
fn dropping_the_wheel_unlinks_its_timers() {
    let ts = timers(3);
    {
        let mut wheel = wheel_at(0);
        wheel.set_timer(ts[0].as_ref(), record, id(0), 0);
        wheel.set_timer(ts[1].as_ref(), record, id(1), 100);
        wheel.set_timer(
            ts[2].as_ref(),
            record,
            id(2),
            10 * i64::from(SOON_WHEEL_SIZE),
        );
    }
    assert!(ts.iter().all(|t| !t.is_active()));
}

#[test]
#[should_panic(expected = "another wheel")]
fn cancelling_through_another_wheel_panics() {
    let t = Box::pin(TWheelTimer::new());
    let mut a = wheel_at(0);
    let mut b = TimerWheel::new(clock());
    a.set_timer(t.as_ref(), record, std::ptr::null_mut(), 100);
    b.cancel_timer(t.as_ref());
}
