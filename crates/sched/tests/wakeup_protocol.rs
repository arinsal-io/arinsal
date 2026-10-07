//! Exhaustive sequentially consistent interleavings of the two wake handoffs.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcessState {
    Running,
    Waiting,
    Queued,
}

#[test]
fn mailbox_publication_cannot_pass_the_wait_probe() {
    // Receiver: publish WAITING, probe ingress, claim WAITING if nonempty.
    // Sender: publish ingress, claim WAITING. Each claim queues exactly once.
    for schedule in schedules(3, 2) {
        let mut state = ProcessState::Running;
        let mut pending = false;
        let mut observed = false;
        let mut queued = 0;
        for (actor, step) in schedule {
            match (actor, step) {
                (0, 0) => state = ProcessState::Waiting,
                (0, 1) => observed = pending,
                (0, 2) if observed && state == ProcessState::Waiting => {
                    state = ProcessState::Queued;
                    queued += 1;
                }
                (1, 0) => pending = true,
                (1, 1) if state == ProcessState::Waiting => {
                    state = ProcessState::Queued;
                    queued += 1;
                }
                _ => {}
            }
        }
        assert_eq!((state, queued), (ProcessState::Queued, 1));
    }
}

#[test]
fn injector_publication_cannot_pass_worker_parking() {
    // Worker: observe epoch, advertise parking, recheck work/epoch, park.
    // Enqueuer: publish work, advance epoch, unpark an advertised worker.
    // `unpark` retains one permit even when it precedes `park`.
    for (schedule, local_work) in schedules(4, 3)
        .into_iter()
        .flat_map(|schedule| [false, true].map(move |local_work| (schedule.clone(), local_work)))
    {
        let mut epoch = 0;
        let mut observed = 0;
        let mut work = false;
        let mut parked = false;
        let mut should_park = false;
        let mut permit = false;
        let mut asleep = false;
        for (actor, step) in schedule {
            match (actor, step) {
                (0, 0) => observed = epoch,
                (0, 1) => parked = true,
                (0, 2) => {
                    should_park = !local_work && !work && epoch == observed;
                    if !should_park {
                        parked = false;
                    }
                }
                (0, 3) if should_park => {
                    asleep = !permit;
                    permit = false;
                }
                (1, 0) => work = true,
                (1, 1) => epoch += 1,
                (1, 2) if parked => {
                    permit = true;
                    asleep = false;
                }
                _ => {}
            }
        }
        assert!(work && !asleep);
    }
}

fn schedules(left: usize, right: usize) -> Vec<Vec<(usize, usize)>> {
    fn visit(
        left: usize,
        right: usize,
        a: usize,
        b: usize,
        prefix: &mut Vec<(usize, usize)>,
        output: &mut Vec<Vec<(usize, usize)>>,
    ) {
        if a == left && b == right {
            output.push(prefix.clone());
            return;
        }
        if a < left {
            prefix.push((0, a));
            visit(left, right, a + 1, b, prefix, output);
            prefix.pop();
        }
        if b < right {
            prefix.push((1, b));
            visit(left, right, a, b + 1, prefix, output);
            prefix.pop();
        }
    }
    let mut output = Vec::new();
    visit(left, right, 0, 0, &mut Vec::new(), &mut output);
    output
}
