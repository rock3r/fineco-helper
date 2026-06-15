//! Functional test of the M8 live-refresh alert wiring
//! (`deploy/alerting/fineco-alert.sh`, plan "Observability → Minimum alerts"
//! scoped to live refresh; the *source* map is `docs/LIVE-REFRESH-GATES.md`).
//!
//! The real script is run against **stubbed** `nft` / `journalctl` / `systemctl`
//! so the named live-refresh alerts (incl. gateway egress deny + scheduled
//! refresh failed) and authenticated-market alerts are proven to fire end-to-end
//! into the configured notifier —
//! without needing a real Fineco event on a host. It also
//! proves the FIRST run only seeds state, the forwarded message is payload-free,
//! a FAILED delivery does not advance state (at-least-once re-fire), a FAILED
//! journal read fails loudly (never a silently-disabled alert source), and the
//! auth alert is scoped to live-refresh tools (a cached-read auth error must not
//! trip it).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn alert_script() -> PathBuf {
    // CARGO_MANIFEST_DIR = crates/fineco-helper; deploy/ is at the repo root.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../deploy/alerting/fineco-alert.sh");
    p
}

fn write_exec(path: &Path, body: &str) {
    fs::write(path, body).expect("write stub");
    let mut perms = fs::metadata(path).expect("stat stub").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("chmod stub");
}

/// A scratch sandbox with stub `nft`/`journalctl`/`systemctl` on PATH.
struct Sandbox {
    root: PathBuf,
    bin: PathBuf,
    state: PathBuf,
    journal: PathBuf,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("fineco-alert-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let bin = root.join("bin");
        let state = root.join("state");
        fs::create_dir_all(&bin).expect("mkdir bin");
        fs::create_dir_all(&state).expect("mkdir state");
        let journal = root.join("journal.txt");

        // `nft list chain inet fineco output` -> the deny rule with the drop counter.
        // STUB_NFT_FAIL=1 exits non-zero (a read error); STUB_NFT_NORULE=1 succeeds
        // but prints a chain WITHOUT the fineco-egress-deny rule (egress not pinned).
        write_exec(
            &bin.join("nft"),
            "#!/bin/sh\n[ \"${STUB_NFT_FAIL:-0}\" = 1 ] && exit 5\n\
             [ \"${STUB_NFT_NORULE:-0}\" = 1 ] && { printf 'type filter hook output priority filter; policy drop;\\n'; exit 0; }\n\
             printf 'meta skuid 999 counter packets %s bytes 0 \
             log prefix \"fineco-egress-deny private-worker \" drop\\n' \"${STUB_EGRESS:-0}\"\n\
             printf 'meta skuid 998 counter packets %s bytes 0 \
             log prefix \"fineco-egress-deny gateway \" drop\\n' \"${STUB_GATEWAY_EGRESS:-0}\"\n",
        );
        // `systemctl show -p NRestarts --value fineco-private-worker` -> a number.
        // With STUB_RESTART_FAIL=1 it exits non-zero (a real systemctl read error).
        write_exec(
            &bin.join("systemctl"),
            "#!/bin/sh\n[ \"${STUB_RESTART_FAIL:-0}\" = 1 ] && exit 4\n\
             printf '%s\\n' \"${STUB_RESTART:-0}\"\n",
        );
        // `journalctl ... --cursor-file=F ...`: write a NON-empty cursor token (a real
        // journalctl writes a cursor string), then emit the canned "new" batch. With
        // STUB_JOURNAL_FAIL=1 it exits non-zero WITHOUT writing — a real read error.
        write_exec(
            &bin.join("journalctl"),
            "#!/bin/sh\nf=''\nfor a in \"$@\"; do case \"$a\" in --cursor-file=*) f=\"${a#--cursor-file=}\";; esac; done\n\
             [ \"${STUB_JOURNAL_FAIL:-0}\" = 1 ] && exit 7\n\
             [ -n \"$f\" ] && printf 'CURSORTOKEN\\n' > \"$f\"\n\
             [ -n \"${STUB_JOURNAL_FILE:-}\" ] && [ -f \"$STUB_JOURNAL_FILE\" ] && cat \"$STUB_JOURNAL_FILE\" || true\n",
        );
        fs::write(&journal, "").expect("write empty journal");
        Sandbox {
            root,
            bin,
            state,
            journal,
        }
    }

    /// Run the alert script. `extra` overrides/adds env (e.g. STUB_JOURNAL_FAIL,
    /// threshold overrides) applied AFTER the deterministic defaults.
    fn run(
        &self,
        alert_command: &str,
        egress: &str,
        restart: &str,
        extra: &[(&str, &str)],
    ) -> std::process::Output {
        let path = format!(
            "{}:{}",
            self.bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut cmd = Command::new("bash");
        cmd.arg(alert_script())
            .env("PATH", path)
            .env("STATE_DIRECTORY", &self.state)
            .env("FINECO_ALERT_COMMAND", alert_command)
            .env("FINECO_ALERT_EGRESS_MIN", "1")
            .env("FINECO_ALERT_GATEWAY_EGRESS_MIN", "1")
            .env("FINECO_ALERT_AUTHFAIL_MIN", "2")
            .env("FINECO_ALERT_MARKET_AUTHFAIL_MIN", "2")
            .env("FINECO_ALERT_MARKET_UPSTREAM_MIN", "2")
            .env("FINECO_ALERT_SPIKE_MIN", "2")
            .env("FINECO_ALERT_RESTART_MIN", "2")
            .env("STUB_EGRESS", egress)
            .env("STUB_GATEWAY_EGRESS", "0")
            .env("STUB_RESTART", restart)
            .env("STUB_JOURNAL_FILE", &self.journal);
        for (k, v) in extra {
            cmd.env(k, v);
        }
        cmd.output().expect("run fineco-alert.sh")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// A window with one of every condition — realistic gateway audit lines
/// (allowlisted by construction: ts/auth_id/tool/data_class/outcome/error_code/
/// duration_ms — never a value). Each refresh line also carries `tool`, so the
/// spike count is the refresh-call count.
const AUDIT_WINDOW: &str = "\
{\"ts\":\"2026-06-06T13:00:00Z\",\"auth_id\":\"owner\",\"tool\":\"private_portfolio_refresh_live_sensitive\",\"data_class\":\"credentialed_live\",\"outcome\":\"error\",\"error_code\":\"refresh_budget_exhausted\",\"duration_ms\":1}\n\
{\"ts\":\"2026-06-06T13:00:01Z\",\"auth_id\":\"owner\",\"tool\":\"private_orders_refresh_live_sensitive\",\"data_class\":\"credentialed_live\",\"outcome\":\"error\",\"error_code\":\"auth_required\",\"duration_ms\":2}\n\
{\"ts\":\"2026-06-06T13:00:02Z\",\"auth_id\":\"owner\",\"tool\":\"private_tax_refresh_live_sensitive\",\"data_class\":\"credentialed_live\",\"outcome\":\"error\",\"error_code\":\"auth_required\",\"duration_ms\":2}\n\
{\"ts\":\"2026-06-06T13:00:03Z\",\"auth_id\":\"owner\",\"tool\":\"private_portfolio_refresh_live_sensitive\",\"data_class\":\"credentialed_live\",\"outcome\":\"error\",\"error_code\":\"refresh_circuit_open\",\"duration_ms\":1}\n\
fineco-helper: refresh failed: the upstream service is temporarily unavailable; please retry.\n";

const ALL_ALERTS: [&str; 8] = [
    "budget exhausted",
    "auth failures",
    "circuit breaker opened",
    "live-refresh spike",
    "egress deny on private worker",
    "egress deny on gateway",
    "private worker restart loop",
    "scheduled portfolio refresh failed",
];

const MARKET_AUDIT_WINDOW: &str = "\
{\"ts\":\"2026-06-14T13:00:00Z\",\"auth_id\":\"owner\",\"tool\":\"market_search_asset\",\"data_class\":\"authenticated_market\",\"outcome\":\"error\",\"error_code\":\"market_auth_required\",\"duration_ms\":2}\n\
{\"ts\":\"2026-06-14T13:00:01Z\",\"auth_id\":\"owner\",\"tool\":\"market_search_asset\",\"data_class\":\"authenticated_market\",\"outcome\":\"error\",\"error_code\":\"market_auth_required\",\"duration_ms\":2}\n\
{\"ts\":\"2026-06-14T13:00:02Z\",\"auth_id\":\"owner\",\"tool\":\"market_search_asset\",\"data_class\":\"authenticated_market\",\"outcome\":\"error\",\"error_code\":\"market_upstream_failure\",\"duration_ms\":2}\n\
{\"ts\":\"2026-06-14T13:00:03Z\",\"auth_id\":\"owner\",\"tool\":\"market_search_asset\",\"data_class\":\"authenticated_market\",\"outcome\":\"error\",\"error_code\":\"fineco_timeout\",\"duration_ms\":2}\n\
{\"ts\":\"2026-06-14T13:00:04Z\",\"auth_id\":\"owner\",\"tool\":\"market_search_asset\",\"data_class\":\"authenticated_market\",\"outcome\":\"error\",\"error_code\":\"market_circuit_open\",\"duration_ms\":1}\n\
{\"ts\":\"2026-06-14T13:00:05Z\",\"auth_id\":\"owner\",\"tool\":\"market_search_asset\",\"data_class\":\"authenticated_market\",\"outcome\":\"ok\",\"duration_ms\":4,\"result_count\":1,\"login_performed\":true,\"session_reused\":true,\"reused_session_401_recovered\":true}\n";

#[test]
fn each_named_live_refresh_alert_fires_and_first_run_only_seeds() {
    let sb = Sandbox::new("fire");
    let sink = sb.root.join("sink.txt");
    let cmd = format!("cat >> {}", sink.display());

    let seed = sb.run(&cmd, "0", "0", &[]);
    assert!(
        seed.status.success(),
        "seed run failed: {}",
        String::from_utf8_lossy(&seed.stderr)
    );
    assert!(
        !sink.exists() || fs::read_to_string(&sink).unwrap().trim().is_empty(),
        "the first run must seed state and emit NO alerts"
    );

    fs::write(&sb.journal, AUDIT_WINDOW).expect("write audit journal");
    // egress=5 (worker), gateway egress=3, restart=4 — one of every counter source.
    let run = sb.run(&cmd, "5", "4", &[("STUB_GATEWAY_EGRESS", "3")]);
    assert!(
        run.status.success(),
        "alert run failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let out = fs::read_to_string(&sink).expect("read sink");
    for needle in ALL_ALERTS {
        assert!(
            out.contains(needle),
            "expected an alert containing {needle:?}; sink was:\n{out}"
        );
    }
    for leaked in ["data_class", "credentialed_live", "auth_id", "duration_ms"] {
        assert!(
            !out.contains(leaked),
            "the forwarded alert must not echo raw journal field {leaked:?}; sink:\n{out}"
        );
    }
}

#[test]
fn authenticated_market_alerts_are_scoped_to_market_audit_lines() {
    let sb = Sandbox::new("market");
    let sink = sb.root.join("sink.txt");
    let cmd = format!("cat >> {}", sink.display());

    assert!(sb.run(&cmd, "0", "0", &[]).status.success(), "seed failed");
    fs::write(&sb.journal, MARKET_AUDIT_WINDOW).expect("write market audit journal");

    let run = sb.run(&cmd, "0", "0", &[]);
    assert!(
        run.status.success(),
        "alert run failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let out = fs::read_to_string(&sink).expect("read sink");
    for needle in [
        "authenticated-market auth failures",
        "authenticated-market upstream failures",
        "authenticated-market circuit breaker opened",
        "authenticated-market reused session recovered after 401",
    ] {
        assert!(
            out.contains(needle),
            "expected market alert {needle:?}; sink:\n{out}"
        );
    }
    for leaked in [
        "data_class",
        "authenticated_market",
        "duration_ms",
        "result_count",
    ] {
        assert!(
            !out.contains(leaked),
            "the forwarded market alert must not echo raw journal field {leaked:?}; sink:\n{out}"
        );
    }
}

#[test]
fn a_failed_delivery_does_not_advance_state_so_alerts_refire() {
    let sb = Sandbox::new("refire");
    let sink = sb.root.join("sink.txt");
    let ok_cmd = format!("cat >> {}", sink.display());

    assert!(
        sb.run(&ok_cmd, "0", "0", &[]).status.success(),
        "seed failed"
    );

    fs::write(&sb.journal, AUDIT_WINDOW).expect("write audit journal");
    let broken = sb.run("false", "5", "4", &[("STUB_GATEWAY_EGRESS", "3")]);
    assert!(
        !broken.status.success(),
        "a failed delivery must make the run exit non-zero"
    );
    assert!(
        !sink.exists() || fs::read_to_string(&sink).unwrap().is_empty(),
        "the broken notifier wrote nothing to the sink"
    );

    let run = sb.run(&ok_cmd, "5", "4", &[("STUB_GATEWAY_EGRESS", "3")]);
    assert!(
        run.status.success(),
        "recovery run failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let out = fs::read_to_string(&sink).expect("read sink");
    for needle in ALL_ALERTS {
        assert!(
            out.contains(needle),
            "after a failed delivery the alert {needle:?} must re-fire; sink:\n{out}"
        );
    }
}

#[test]
fn a_new_gateway_counter_baselines_on_an_upgraded_install() {
    // Adding the gateway egress source to an ALREADY-SEEDED install (an upgrade):
    // the gateway baseline file does not exist yet, so the first run must BASELINE the
    // current value — NOT fire a one-time false alert for pre-existing denies.
    let sb = Sandbox::new("upgrade");
    let sink = sb.root.join("sink.txt");
    let cmd = format!("cat >> {}", sink.display());

    assert!(sb.run(&cmd, "0", "0", &[]).status.success(), "seed failed");
    // Simulate the pre-upgrade state: the gateway baseline never existed.
    let _ = fs::remove_file(sb.state.join("gateway-egress-counter"));

    // The gateway counter is already non-zero; the first sight must not alert.
    let first = sb.run(&cmd, "0", "0", &[("STUB_GATEWAY_EGRESS", "7")]);
    assert!(
        first.status.success(),
        "first run failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        !fs::read_to_string(&sink)
            .unwrap_or_default()
            .contains("egress deny on gateway"),
        "a newly-added gateway counter must baseline on first sight, not alert"
    );

    // A genuine increase AFTER the baseline does alert.
    let second = sb.run(&cmd, "0", "0", &[("STUB_GATEWAY_EGRESS", "9")]);
    assert!(second.status.success());
    assert!(
        fs::read_to_string(&sink)
            .unwrap_or_default()
            .contains("egress deny on gateway"),
        "a real increase after the baseline must alert"
    );
}

#[test]
fn the_new_gateway_baseline_persists_even_when_a_run_fails_delivery() {
    // Regression: the new gateway counter seeds its baseline IMMEDIATELY (not gated on
    // delivery), so a failed-delivery run can't re-reset it and lose denies in that
    // window. Seed -> drop the gateway baseline (simulate upgrade) -> a run with a
    // BROKEN notifier must still persist the baseline -> a later run alerts on the real
    // delta, not a false full-counter alert.
    let sb = Sandbox::new("gwpersist");
    let sink = sb.root.join("sink.txt");
    let cmd = format!("cat >> {}", sink.display());
    assert!(sb.run(&cmd, "0", "0", &[]).status.success(), "seed failed");
    let gw_state = sb.state.join("gateway-egress-counter");
    let _ = fs::remove_file(&gw_state);

    // Broken notifier (a worker deny fires + fails to deliver), gateway counter = 7.
    let broken = sb.run("false", "5", "0", &[("STUB_GATEWAY_EGRESS", "7")]);
    assert!(
        !broken.status.success(),
        "a failed delivery must exit non-zero"
    );
    assert_eq!(
        fs::read_to_string(&gw_state).unwrap_or_default().trim(),
        "7",
        "the gateway baseline must persist (be seeded) despite the failed delivery"
    );

    // A later run at gateway = 9 (ok notifier) alerts on the +2 delta, not a false +9.
    let ok = sb.run(&cmd, "0", "0", &[("STUB_GATEWAY_EGRESS", "9")]);
    assert!(ok.status.success());
    assert!(
        fs::read_to_string(&sink)
            .unwrap_or_default()
            .contains("egress deny on gateway (counter +2)"),
        "must alert on the real +2 delta from the persisted baseline"
    );
}

#[test]
fn a_failed_journal_read_fails_loudly_but_counter_alerts_still_fire() {
    // Codex P2 + Cursor Med: a journalctl error must surface as a failed unit (not a
    // green timer with silently-disabled alerts), yet the journal-INDEPENDENT counter
    // alerts (egress, restart) must still fire in the same run.
    let sb = Sandbox::new("loud");
    let sink = sb.root.join("sink.txt");
    let cmd = format!("cat >> {}", sink.display());

    assert!(sb.run(&cmd, "0", "0", &[]).status.success(), "seed failed");

    fs::write(&sb.journal, AUDIT_WINDOW).expect("write audit journal");
    let failed = sb.run(&cmd, "5", "4", &[("STUB_JOURNAL_FAIL", "1")]);
    assert!(
        !failed.status.success(),
        "a failed journal read must exit non-zero (alert source unwired)"
    );
    assert!(
        String::from_utf8_lossy(&failed.stderr).contains("UNWIRED"),
        "the failure must be explained, not swallowed"
    );
    let out = fs::read_to_string(&sink).unwrap_or_default();
    assert!(
        out.contains("egress deny on private worker")
            && out.contains("private worker restart loop"),
        "the journal-independent counter alerts must still fire; sink:\n{out}"
    );
    for j in [
        "budget exhausted",
        "circuit breaker opened",
        "live-refresh spike",
    ] {
        assert!(
            !out.contains(j),
            "no journal alert should fire on a journal read failure: {j}"
        );
    }
}

#[test]
fn an_nft_read_failure_fails_loudly() {
    // Codex P2: nft failing must not be read as counter 0 (which would mask real
    // denies) — it fails loudly and does not advance state.
    let sb = Sandbox::new("nft");
    let sink = sb.root.join("sink.txt");
    let cmd = format!("cat >> {}", sink.display());
    assert!(sb.run(&cmd, "0", "0", &[]).status.success(), "seed failed");

    let failed = sb.run(&cmd, "5", "0", &[("STUB_NFT_FAIL", "1")]);
    assert!(
        !failed.status.success(),
        "an nft read failure must exit non-zero"
    );
    assert!(
        String::from_utf8_lossy(&failed.stderr).contains("nftables egress counter"),
        "the nft failure must be explained"
    );
}

#[test]
fn a_restart_read_failure_fails_loudly() {
    // Cursor MED + Codex P2: a systemctl NRestarts read failure must not be recorded
    // as 0 (which would overwrite the baseline and suppress restart-loop alerts).
    let sb = Sandbox::new("restart");
    let sink = sb.root.join("sink.txt");
    let cmd = format!("cat >> {}", sink.display());
    assert!(sb.run(&cmd, "0", "0", &[]).status.success(), "seed failed");

    let failed = sb.run(&cmd, "0", "5", &[("STUB_RESTART_FAIL", "1")]);
    assert!(
        !failed.status.success(),
        "a restart read failure must exit non-zero"
    );
    assert!(
        String::from_utf8_lossy(&failed.stderr).contains("restart count"),
        "the restart read failure must be explained"
    );
}

#[test]
fn the_seed_fails_loudly_if_a_counter_source_is_unreadable() {
    // Cursor MED: the first-run seed must not record a bogus 0 baseline when nft or
    // systemctl is unreadable (that would fire a false delta on the next good read).
    let sb = Sandbox::new("seedfail");
    let sink = sb.root.join("sink.txt");
    let cmd = format!("cat >> {}", sink.display());

    let failed = sb.run(&cmd, "0", "0", &[("STUB_NFT_FAIL", "1")]);
    assert!(
        !failed.status.success(),
        "the seed must fail loudly on an unreadable source"
    );
    assert!(
        !sb.state.join("seeded").exists(),
        "a failed seed must not record the seed marker"
    );

    // A clean run then seeds normally.
    let seed = sb.run(&cmd, "0", "0", &[]);
    assert!(
        seed.status.success(),
        "clean seed failed: {}",
        String::from_utf8_lossy(&seed.stderr)
    );
    assert!(
        sb.state.join("seeded").exists(),
        "the clean seed records the seed marker"
    );
}

#[test]
fn the_seed_fails_loudly_if_the_journal_is_unreadable() {
    // Codex P2: a transient journal read failure during the seed must NOT mark
    // seeded without a cursor (else the next run reads from the start and re-fires
    // historical audit entries). Fail loud and retry.
    let sb = Sandbox::new("seedjournal");
    let sink = sb.root.join("sink.txt");
    let cmd = format!("cat >> {}", sink.display());

    let failed = sb.run(&cmd, "0", "0", &[("STUB_JOURNAL_FAIL", "1")]);
    assert!(
        !failed.status.success(),
        "the seed must fail loudly when the journal is unreadable"
    );
    assert!(
        !sb.state.join("seeded").exists(),
        "a failed journal seed must not record the seed marker"
    );

    // A clean run then seeds normally.
    let seed = sb.run(&cmd, "0", "0", &[]);
    assert!(
        seed.status.success(),
        "clean seed failed: {}",
        String::from_utf8_lossy(&seed.stderr)
    );
    assert!(
        sb.state.join("seeded").exists(),
        "the clean seed marks seeded"
    );
}

#[test]
fn a_counter_reset_is_treated_as_a_new_delta() {
    // Codex P2 x2: a reboot / nft-reapply resets nft + NRestarts below the saved
    // baseline; the post-reset value is the delta, not a negative no-op that misses
    // events.
    let sb = Sandbox::new("reset");
    let sink = sb.root.join("sink.txt");
    let cmd = format!("cat >> {}", sink.display());
    assert!(
        sb.run(&cmd, "100", "9", &[]).status.success(),
        "seed failed"
    );

    // egress 100 -> 3, restart 9 -> 4 (both reset below baseline).
    let run = sb.run(&cmd, "3", "4", &[]);
    assert!(
        run.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let out = fs::read_to_string(&sink).expect("read sink");
    assert!(
        out.contains("egress deny on private worker (counter +3)"),
        "a reset egress counter must use the post-reset value as the delta; sink:\n{out}"
    );
    assert!(
        out.contains("private worker restart loop (NRestarts +4)"),
        "a reset restart count must use the post-reset value as the delta; sink:\n{out}"
    );
}

#[test]
fn each_source_baseline_advances_independently() {
    // Cursor Med: when the journal source is broken, the egress/restart baselines
    // must still advance (delivery succeeded) so those counter alerts do NOT re-fire
    // every run while the journal stays down.
    let sb = Sandbox::new("persource");
    let sink = sb.root.join("sink.txt");
    let cmd = format!("cat >> {}", sink.display());
    assert!(sb.run(&cmd, "0", "0", &[]).status.success(), "seed failed");

    // Run A: journal broken, egress jumps to 5 -> egress alert fires, exit non-zero.
    let a = sb.run(&cmd, "5", "0", &[("STUB_JOURNAL_FAIL", "1")]);
    assert!(!a.status.success(), "journal failure must exit non-zero");
    // Run B: journal still broken, egress unchanged -> NO new egress alert (the
    // egress baseline advanced in run A despite the journal failure).
    let _b = sb.run(&cmd, "5", "0", &[("STUB_JOURNAL_FAIL", "1")]);
    let egress_alerts = fs::read_to_string(&sink)
        .unwrap_or_default()
        .matches("egress deny on private worker")
        .count();
    assert_eq!(
        egress_alerts, 1,
        "the egress alert must fire once, not re-fire while the journal is broken"
    );
}

#[test]
fn a_missing_egress_deny_rule_is_treated_as_unreadable() {
    // Cursor Med: nft ok but no fineco-egress-deny rule (egress not pinned) must not
    // read as "0 denies"; as a first run it makes the seed fail loud.
    let sb = Sandbox::new("norule");
    let sink = sb.root.join("sink.txt");
    let cmd = format!("cat >> {}", sink.display());
    let failed = sb.run(&cmd, "0", "0", &[("STUB_NFT_NORULE", "1")]);
    assert!(
        !failed.status.success(),
        "a missing egress-deny rule must not silently pass"
    );
    assert!(
        String::from_utf8_lossy(&failed.stderr).contains("egress-deny rule is absent"),
        "the missing rule must be explained"
    );
}

#[test]
fn a_missing_cursor_reads_from_the_start_and_still_alerts() {
    // Codex P2: if the seed wrote no cursor (the gateway had not logged yet), the
    // next run must read from the START and preserve the first events, not skip them.
    let sb = Sandbox::new("nocursor");
    let sink = sb.root.join("sink.txt");
    let cmd = format!("cat >> {}", sink.display());
    assert!(sb.run(&cmd, "0", "0", &[]).status.success(), "seed failed");

    // Simulate "no cursor was seeded".
    let _ = fs::remove_file(sb.state.join("journal.cursor"));
    fs::write(&sb.journal, AUDIT_WINDOW).expect("write audit journal");
    let run = sb.run(&cmd, "0", "0", &[]);
    assert!(
        run.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let out = fs::read_to_string(&sink).expect("read sink");
    assert!(
        out.contains("budget exhausted") && out.contains("circuit breaker opened"),
        "a missing cursor must read from the start and still fire the journal alerts; sink:\n{out}"
    );
}

#[test]
fn the_auth_alert_is_scoped_to_live_refresh_tools() {
    // Cursor Med: error_code auth_required on a NON-refresh tool (a cached read)
    // must not count toward the live-refresh auth-failure alert.
    let sb = Sandbox::new("authscope");
    let sink = sb.root.join("sink.txt");
    let cmd = format!("cat >> {}", sink.display());

    assert!(sb.run(&cmd, "0", "0", &[]).status.success(), "seed failed");

    // Two refresh auth failures + one cached-read auth error. With the threshold at
    // 3 and proper scoping the count is 2 (< 3) -> NO auth alert. (Unscoped it would
    // be 3 and fire.)
    let window = "\
{\"ts\":\"2026-06-06T13:00:00Z\",\"auth_id\":\"owner\",\"tool\":\"private_orders_refresh_live_sensitive\",\"data_class\":\"credentialed_live\",\"outcome\":\"error\",\"error_code\":\"auth_required\",\"duration_ms\":2}\n\
{\"ts\":\"2026-06-06T13:00:01Z\",\"auth_id\":\"owner\",\"tool\":\"private_tax_refresh_live_sensitive\",\"data_class\":\"credentialed_live\",\"outcome\":\"error\",\"error_code\":\"auth_required\",\"duration_ms\":2}\n\
{\"ts\":\"2026-06-06T13:00:02Z\",\"auth_id\":\"owner\",\"tool\":\"orders_get_latest_monitor\",\"data_class\":\"sensitive_private_cached\",\"outcome\":\"error\",\"error_code\":\"auth_required\",\"duration_ms\":0}\n";
    fs::write(&sb.journal, window).expect("write window");
    let run = sb.run(
        &cmd,
        "0",
        "0",
        &[
            ("FINECO_ALERT_AUTHFAIL_MIN", "3"),
            ("FINECO_ALERT_SPIKE_MIN", "99"),
        ],
    );
    assert!(
        run.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let out = fs::read_to_string(&sink).unwrap_or_default();
    assert!(
        !out.contains("auth failures"),
        "a cached-read auth error must not trip the live-refresh auth alert; sink:\n{out}"
    );
}
