//! Running independent jobs concurrently without letting scheduling change the
//! answer.
//!
//! # The result must not depend on who finished first
//!
//! Every job writes into a fixed slot indexed by its position in the execution
//! plan, and the slots are drained in plan order once the scope ends. So the
//! report is byte-identical whatever the worker count and whatever order the
//! backends happened to complete in — which is what makes `--jobs 2` safe to
//! offer at all. The same pattern M7's coverage decoder uses, for the same
//! reason.
//!
//! # Separate limits, because the resources are not alike
//!
//! One number cannot bound this work. Cargo serialises on its own target-
//! directory lock, so extra build workers mostly wait; Valgrind is CPU- and
//! memory-hungry per process; the analyzer runs in a container with its own
//! solver. A single `--jobs 8` would either starve the build or oversubscribe
//! the analyzers.
//!
//! What concurrency actually buys here is **overlap between phases**: one
//! contract's Memcheck run proceeds while another's harness compiles. Within a
//! backend, builds still serialise on Cargo's lock — deliberately, because
//! per-job target directories would rebuild `core`, the library and every
//! dependency per job and leave hundreds of megabytes behind. That trade was
//! settled in M5 and is not reopened here.
//!
//! # Defaults are conservative
//!
//! One worker unless asked otherwise. A developer debugging a finding wants a
//! readable, reproducible run; a CI job that wants throughput can say so, and
//! the measured gain is real: over the eighteen `crypto-bigint` audit contracts
//! and twenty-one jobs, `--jobs 2` took 2:25 against 3:58 sequentially — 1.6x,
//! despite the Cargo lock, because overlapping a Memcheck run with another
//! contract's build is where the time goes.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use serde::Serialize;

/// How many jobs of each kind may run at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Limits {
    /// Generated dynamic checking, including its Cargo builds and Valgrind
    /// processes.
    pub generated: usize,
    /// Symbolic verification, including its Cargo builds and analyzer
    /// containers.
    pub symbolic: usize,
}

impl Default for Limits {
    /// One of each: deterministic, readable, and what a developer reading a
    /// finding wants.
    fn default() -> Limits {
        Limits {
            generated: 1,
            symbolic: 1,
        }
    }
}

impl Limits {
    /// The limits `--jobs n` asks for.
    ///
    /// The same number for both backends rather than a split, because the two
    /// run in separate stages and never compete with each other for a slot.
    /// Zero is read as one: a run that schedules nothing is not a faster run,
    /// it is a run that does nothing.
    pub fn uniform(jobs: usize) -> Limits {
        let jobs = jobs.max(1);
        Limits {
            generated: jobs,
            symbolic: jobs,
        }
    }
}

/// Runs `job` over every item, `workers` at a time, returning results in the
/// **input** order.
///
/// `job` must be callable from several threads at once. Anything it mutates has
/// to be its own; everything shared is taken by reference.
///
/// A panic in one job poisons that slot's lock, and draining it panics in turn
/// rather than silently producing a short result vector. A missing result is
/// not a safe thing to guess at: it would shift every later result onto the
/// wrong contract.
pub fn in_order<T, R, F>(items: &[T], workers: usize, job: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(usize, &T) -> R + Sync,
{
    if items.is_empty() {
        return Vec::new();
    }
    // One worker is the common case and the default. Running it on this thread
    // keeps a single-job run free of thread spawning, and -- more usefully --
    // keeps a panic's backtrace pointing at the job rather than at a worker.
    if workers <= 1 {
        return items
            .iter()
            .enumerate()
            .map(|(index, item)| job(index, item))
            .collect();
    }
    let next = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<R>>> = items.iter().map(|_| Mutex::new(None)).collect();
    let workers = workers.min(items.len());
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= items.len() {
                    return;
                }
                let result = job(index, &items[index]);
                *slots[index].lock().expect("no panic holds this lock") = Some(result);
            });
        }
    });
    slots
        .into_iter()
        .map(|slot| {
            slot.into_inner()
                .expect("a job panicked, so its result cannot be placed")
                .expect("every slot is filled before the scope ends")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Results come back in input order however long each job takes, so the
    /// report cannot depend on which backend finished first.
    #[test]
    fn results_are_ordered_by_input_not_by_completion() {
        let items: Vec<usize> = (0..16).collect();
        // Reverse the durations, so completion order is the opposite of input
        // order and an implementation that collected as results arrived would
        // produce a reversed vector.
        let run = |workers: usize| {
            in_order(&items, workers, |_, item| {
                std::thread::sleep(std::time::Duration::from_millis((16 - *item as u64) * 2));
                *item * 10
            })
        };
        let expected: Vec<usize> = items.iter().map(|item| item * 10).collect();
        assert_eq!(run(1), expected);
        assert_eq!(run(4), expected, "four workers must agree with one");
    }

    /// Every item runs exactly once, whatever the worker count. A job claimed
    /// twice would double-count evidence; one never claimed would leave a
    /// requirement silently unanswered.
    #[test]
    fn every_item_runs_exactly_once() {
        let items: Vec<usize> = (0..64).collect();
        for workers in [1, 2, 8, 100] {
            let counts: Vec<AtomicUsize> = items.iter().map(|_| AtomicUsize::new(0)).collect();
            let indices = in_order(&items, workers, |index, item| {
                counts[index].fetch_add(1, Ordering::Relaxed);
                (index, *item)
            });
            for (index, count) in counts.iter().enumerate() {
                assert_eq!(
                    count.load(Ordering::Relaxed),
                    1,
                    "item {index} ran the wrong number of times with {workers} worker(s)"
                );
            }
            // And each result landed on its own item.
            for (index, (seen, item)) in indices.iter().enumerate() {
                assert_eq!(*seen, index);
                assert_eq!(*item, items[index]);
            }
        }
    }

    /// An empty plan schedules nothing and spawns nothing.
    #[test]
    fn nothing_to_do_runs_nothing() {
        let empty: Vec<usize> = Vec::new();
        let results = in_order(&empty, 8, |_, _: &usize| unreachable!("nothing to run"));
        assert!(results.is_empty());
    }

    /// Zero workers is one worker: a run that schedules nothing is not faster,
    /// it does nothing.
    #[test]
    fn zero_jobs_is_one_job() {
        assert_eq!(Limits::uniform(0), Limits::uniform(1));
        assert_eq!(Limits::uniform(0), Limits::default());
        let items = [1, 2, 3];
        assert_eq!(in_order(&items, 0, |_, item| *item * 2), vec![2, 4, 6]);
    }
}
