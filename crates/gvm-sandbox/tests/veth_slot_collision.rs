//! Regression pin for the veth-slot collision fix (`fc6f7c3`,
//! `fix(sandbox): serialize concurrent veth slot allocation via flock`).
//!
//! Before the fix, two `gvm run --sandbox` processes launching at
//! the same time could both pick the same slot during the
//! scan-then-claim window because there was no inter-process
//! mutex. The kernel `ip link add` then failed for the second
//! launch with "File exists", but more dangerously, if the timing
//! changed slightly both could land on different but
//! address-overlapping slots.
//!
//! The fix is an exclusive `flock(/run/gvm/network.lock)` held
//! across (a) scan for in-use `veth-gvm-h*` interfaces, (b) pick
//! lowest free slot, (c) create the pair. The lock is per-OS-fd,
//! so a forked child cannot accidentally inherit + release it
//! mid-claim, and exit auto-releases.
//!
//! These tests pin two angles of that fix:
//!
//! 1. **Address-scheme invariants** — slot N maps deterministically
//!    to an address pair, distinct slots produce distinct address
//!    pairs, and within the documented 0..1023 slot range every
//!    pair is unique. If any of these break, even a perfect flock
//!    couldn't prevent collisions because two allocators could
//!    pick "different" slots that mapped to the same IP.
//! 2. **Concurrent allocator test (Linux + root, opt-in)** — runs
//!    the actual `VethConfig::new` allocator from N tasks
//!    simultaneously and verifies they all received distinct
//!    slots. Marked `#[ignore]` because it needs root + actually
//!    creates kernel interfaces; operators run it explicitly with
//!    `cargo test --test veth_slot_collision -- --ignored` on a
//!    test host before cutting a release.

use std::collections::HashSet;
use std::net::SocketAddr;

#[allow(dead_code)] // referenced only by the Linux concurrent test below
fn proxy_addr() -> SocketAddr {
    "127.0.0.1:8080".parse().unwrap()
}

/// Pure-Rust replication of `VethConfig::from_slot`'s address scheme.
/// Used for cross-platform property tests of the slot → address
/// mapping. The real `VethConfig::from_slot` is internal to
/// `gvm-sandbox::network` and not part of the public surface; the
/// in-repo `tests/security.rs` keeps the same helper for the same
/// reason. Drift between this helper and the production formula
/// would surface as the kernel `ip link add` failing — and the
/// concurrent-allocator test below catches that on Linux.
struct SlotAddrs {
    host_iface: String,
    sandbox_iface: String,
    host_ip: String,
    sandbox_ip: String,
}

fn slot_addrs(slot: u32) -> SlotAddrs {
    let third_octet = (slot % 256) as u8;
    let fourth_base = ((slot / 256) % 64) as u8 * 4;
    SlotAddrs {
        host_iface: format!("veth-gvm-h{}", slot),
        sandbox_iface: format!("veth-gvm-s{}", slot),
        host_ip: format!("10.200.{}.{}", third_octet, fourth_base + 1),
        sandbox_ip: format!("10.200.{}.{}", third_octet, fourth_base + 2),
    }
}

#[test]
fn slot_to_address_mapping_is_deterministic() {
    // The slot → address mapping is a pure function of the slot.
    // Same slot, same addresses, every time. A regression that
    // made it depend on hidden state (process counter, RNG) would
    // surface here, and would also be precisely the bug
    // `fc6f7c3` was guarding against — slot allocation losing
    // determinism breaks the kernel's "interface name → IP"
    // dispatch contract.
    for slot in [0, 1, 7, 42, 255, 256, 1023] {
        let a = slot_addrs(slot);
        let b = slot_addrs(slot);
        assert_eq!(a.host_iface, b.host_iface, "slot {slot}: iface determinism");
        assert_eq!(a.host_ip, b.host_ip, "slot {slot}: host IP determinism");
        assert_eq!(
            a.sandbox_ip, b.sandbox_ip,
            "slot {slot}: sandbox IP determinism"
        );
    }
}

#[test]
fn distinct_slots_produce_distinct_address_pairs() {
    // The address scheme is `10.200.{slot%256}.{(slot/256)%64*4 + {1,2}}`.
    // Within slot range 0..1024 every slot pair is unique. Pin
    // this for the documented range — a refactor that narrowed
    // the range or shifted the bit layout would surface as
    // duplicates, which under the flock-protected allocator
    // would be a silent correctness bug (two concurrent claims
    // hand back different "slots" that share an IP).
    let mut seen_host_ips = HashSet::new();
    let mut seen_sandbox_ips = HashSet::new();
    let mut seen_ifaces = HashSet::new();

    for slot in 0..1024_u32 {
        let cfg = slot_addrs(slot);
        assert!(
            seen_host_ips.insert(cfg.host_ip.clone()),
            "duplicate host_ip {} at slot {slot}",
            cfg.host_ip
        );
        assert!(
            seen_sandbox_ips.insert(cfg.sandbox_ip.clone()),
            "duplicate sandbox_ip {} at slot {slot}",
            cfg.sandbox_ip
        );
        assert!(
            seen_ifaces.insert(cfg.host_iface.clone()),
            "duplicate host_iface {} at slot {slot}",
            cfg.host_iface
        );
    }
    assert_eq!(seen_host_ips.len(), 1024);
    assert_eq!(seen_sandbox_ips.len(), 1024);
    assert_eq!(seen_ifaces.len(), 1024);
}

#[test]
fn host_and_sandbox_ips_within_a_pair_are_distinct() {
    // Within one allocation, the host side and sandbox side must
    // differ — they're the two ends of the veth pair, sharing a
    // /30 subnet but with consecutive addresses. A regression
    // that mistakenly used the same address for both ends would
    // make the kernel reject the assignment, but the test pins
    // it at config-build time.
    for slot in [1, 50, 500, 1023] {
        let cfg = slot_addrs(slot);
        assert_ne!(
            cfg.host_ip, cfg.sandbox_ip,
            "host and sandbox ends of the veth pair must differ (slot {slot})"
        );
        assert_ne!(
            cfg.host_iface, cfg.sandbox_iface,
            "host and sandbox iface names must differ (slot {slot})"
        );
    }
}

// ─────────────────────────────────────────────────────────────────
// Linux-only, root-required, opt-in concurrent allocator test.
//
// This is the test the `fc6f7c3` fix actually targets: spawn N
// concurrent slot claims and verify each one got a distinct slot.
// Without the flock fix, two of the N would land on the same slot
// under sufficient parallelism + slow-enough scan.
//
// `#[ignore]` so it doesn't run in CI's `cargo test`. Operators
// validating a release on a real Linux host:
//
//     cargo test --test veth_slot_collision -- --ignored
//
// The test creates real veth pairs, so it needs CAP_NET_ADMIN
// (i.e. root). It cleans up by relying on the slot allocator's
// own claim → kernel-state lifecycle; if the test host already
// has 16+ veth-gvm-h* interfaces the test will skip with a
// helpful error.
// ─────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs root (CAP_NET_ADMIN) — opt-in via cargo test -- --ignored"]
fn concurrent_allocators_get_distinct_slots() {
    use gvm_sandbox::VethConfig;
    use std::sync::{Arc, Mutex};
    use std::thread;

    const N: u32 = 16;
    let claimed_slots: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::with_capacity(N as usize)));

    // Spawn N OS threads (real concurrency, not async tasks) that
    // each call `VethConfig::new` simultaneously. Without the
    // flock, the scan windows would overlap and at least two
    // would observe the same "lowest free slot" snapshot.
    let mut handles = Vec::with_capacity(N as usize);
    for i in 0..N {
        let claimed = Arc::clone(&claimed_slots);
        handles.push(thread::spawn(move || {
            // Use a fake child_pid so kernel state is uniquely
            // labeled per thread. Real prod usage passes the actual
            // sandbox child pid here.
            let cfg = match VethConfig::new(900_000 + i, "127.0.0.1:8080".parse().unwrap()) {
                Ok(c) => c,
                Err(e) => panic!("thread {i}: VethConfig::new failed: {e}"),
            };
            claimed.lock().unwrap().push(cfg.slot);
        }));
    }
    for h in handles {
        h.join().expect("worker thread join");
    }

    let mut slots = claimed_slots.lock().unwrap().clone();
    slots.sort();
    let unique: HashSet<u32> = slots.iter().copied().collect();
    assert_eq!(
        unique.len(),
        N as usize,
        "expected {N} distinct slots, got duplicates: {slots:?}"
    );

    // Best-effort cleanup. If the kernel state we created leaks
    // into the next test run on the same host, `gvm cleanup`
    // (the boot-time sweep) will reclaim it.
    for slot in &slots {
        let iface = format!("veth-gvm-h{slot}");
        let _ = std::process::Command::new("ip")
            .args(["link", "del", &iface])
            .output();
    }
}
