//! Guards the security-critical content of the deployment artifacts under
//! `deploy/` (see the design spec, "LXC Hardening"), so the systemd hardening, the
//! loopback-only gateway bind, and the no-network store-server can't be silently
//! weakened. This is a static content check, not a live systemd run (the real
//! `systemd-analyze` verification happens on the target host).
//!
//! All checks parse **effective, non-comment** directives — a commented-out or
//! later-overridden line cannot satisfy a guard.

use std::path::PathBuf;

fn deploy_file(rel: &str) -> String {
    // CARGO_MANIFEST_DIR = crates/fineco-helper; deploy/ is at the repo root.
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../deploy");
    path.push(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Active (non-comment, non-blank) lines, trimmed.
fn active_lines(body: &str) -> Vec<String> {
    body.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// The effective (last-wins) value of a `Key=Value` systemd directive among the
/// active lines.
fn effective<'a>(lines: &'a [String], key: &str) -> Option<&'a str> {
    lines.iter().rev().find_map(|line| {
        let (k, v) = line.split_once('=')?;
        (k.trim() == key).then(|| v.trim())
    })
}

/// The effective value of an `Environment=VAR=value` line (last-wins).
fn effective_env<'a>(lines: &'a [String], var: &str) -> Option<&'a str> {
    lines.iter().rev().find_map(|line| {
        let rest = line.strip_prefix("Environment=")?;
        let (k, v) = rest.split_once('=')?;
        (k == var).then(|| v.trim())
    })
}

/// Single-value hardening directives both units must set to exactly this value
/// (plan "LXC Hardening"); checked as the *effective* value, so a later override
/// would fail the guard.
const REQUIRED_HARDENING: &[(&str, &str)] = &[
    ("NoNewPrivileges", "true"),
    ("PrivateTmp", "true"),
    ("ProtectSystem", "strict"),
    ("ProtectHome", "true"),
    ("RestrictSUIDSGID", "true"),
    ("RestrictNamespaces", "true"),
];

#[test]
fn both_units_apply_the_required_hardening() {
    for unit in [
        "systemd/fineco-store-server.service",
        "systemd/fineco-gateway.service",
        "systemd/fineco-private-worker.service",
    ] {
        let lines = active_lines(&deploy_file(unit));
        for (key, value) in REQUIRED_HARDENING {
            assert_eq!(
                effective(&lines, key),
                Some(*value),
                "{unit}: effective `{key}` must be `{value}`"
            );
        }
        // SystemCallFilter is additive — require the @system-service baseline and
        // the correct single-`~` denylist (one `~` inverts the whole list; the
        // `~@privileged ~@resources` form ignores @resources, leaving it allowed).
        assert!(
            lines
                .iter()
                .any(|l| l == "SystemCallFilter=@system-service"),
            "{unit}: missing the @system-service syscall filter"
        );
        assert!(
            lines
                .iter()
                .any(|l| l == "SystemCallFilter=~@privileged @resources"),
            "{unit}: must deny @privileged + @resources in one inverted list"
        );
        assert!(
            !lines.iter().any(|l| l.contains("~@resources")),
            "{unit}: `~@resources` parses as a literal token and is ignored"
        );
    }
}

#[test]
fn privileged_oneshot_units_are_hardened() {
    // The egress-set (root + CAP_NET_ADMIN) and backup (DB owner) oneshots are
    // privileged helpers — they must carry the core sandbox so a compromise of the
    // resolver/awk/age path is contained, not run with full root.
    for unit in [
        "systemd/fineco-refresh-egress-set.service",
        "systemd/fineco-backup.service",
    ] {
        let lines = active_lines(&deploy_file(unit));
        for (key, value) in [
            ("NoNewPrivileges", "true"),
            ("ProtectSystem", "strict"),
            ("PrivateTmp", "true"),
            ("RestrictNamespaces", "true"),
        ] {
            assert_eq!(
                effective(&lines, key),
                Some(value),
                "{unit}: effective `{key}` must be `{value}`"
            );
        }
        // Each clamps its capabilities + address families (the egress-set to
        // CAP_NET_ADMIN/netlink, the backup to none/AF_UNIX) rather than keeping
        // full root.
        assert!(
            effective(&lines, "CapabilityBoundingSet").is_some(),
            "{unit}: must clamp CapabilityBoundingSet"
        );
        assert!(
            effective(&lines, "RestrictAddressFamilies").is_some(),
            "{unit}: must restrict address families"
        );
    }
    // The egress-set keeps exactly the one capability it needs (nftables).
    let egress = active_lines(&deploy_file("systemd/fineco-refresh-egress-set.service"));
    assert_eq!(
        effective(&egress, "CapabilityBoundingSet"),
        Some("CAP_NET_ADMIN"),
        "the egress-set must keep only CAP_NET_ADMIN"
    );
    // The backup needs no capability at all.
    let backup = active_lines(&deploy_file("systemd/fineco-backup.service"));
    assert_eq!(
        effective(&backup, "CapabilityBoundingSet"),
        Some(""),
        "the backup must drop all capabilities"
    );
}

#[test]
fn store_server_runs_as_fineco_store_with_no_network_and_the_live_group() {
    let lines = active_lines(&deploy_file("systemd/fineco-store-server.service"));
    // M8: the store-server is the `fineco-store` user (the DB owner), NOT the
    // credential worker (`fineco-worker`).
    assert_eq!(
        effective(&lines, "User"),
        Some("fineco-store"),
        "store-server must run as fineco-store (distinct from the credential worker)"
    );
    assert_eq!(
        effective(&lines, "PrivateNetwork"),
        Some("true"),
        "store-server must have no network (it only speaks Unix sockets)"
    );
    assert_eq!(
        effective(&lines, "RestrictAddressFamilies"),
        Some("AF_UNIX"),
        "store-server must be restricted to AF_UNIX only"
    );
    // No INET anywhere (it clients the live socket over pathname AF_UNIX, which
    // works under PrivateNetwork).
    assert!(
        !lines.iter().any(|l| l.contains("AF_INET")),
        "store-server must not allow INET"
    );
    // It joins fineco-ipc-live so the controller can connect to the worker's live
    // socket — but it is NOT a member of the store/refresh groups (it owns those
    // socket dirs). It must NEVER hold the credential worker's group.
    let groups = effective(&lines, "SupplementaryGroups").expect("store-server sets groups");
    assert!(
        groups.contains("fineco-ipc-live"),
        "store-server must join fineco-ipc-live to client the live socket, got `{groups}`"
    );
    // The refresh controller is wired (the second socket).
    assert_eq!(
        effective_env(&lines, "FINECO_REFRESH_SOCKET_MODE"),
        Some("0660"),
        "store-server must serve refresh-control.sock group-shared"
    );
    assert!(
        effective_env(&lines, "FINECO_LIVE_SOCKET").is_some(),
        "store-server (controller) must target the worker's live socket"
    );
}

#[test]
fn gateway_joins_store_and_refresh_groups_but_never_live() {
    let lines = active_lines(&deploy_file("systemd/fineco-gateway.service"));
    let bind = effective_env(&lines, "FINECO_GATEWAY_BIND").expect("gateway sets a bind");
    assert!(
        bind.starts_with("127.0.0.1:"),
        "gateway must bind loopback, got `{bind}`"
    );
    assert!(
        !bind.contains("0.0.0.0") && !bind.starts_with("[::]"),
        "gateway must not bind non-loopback, got `{bind}`"
    );
    let groups = effective(&lines, "SupplementaryGroups").expect("gateway sets groups");
    assert!(
        groups.contains("fineco-ipc-store"),
        "gateway must join fineco-ipc-store (cached reads), got `{groups}`"
    );
    assert!(
        groups.contains("fineco-ipc-refresh"),
        "gateway must join fineco-ipc-refresh (live refresh), got `{groups}`"
    );
    // The crown-jewel invariant: the internet-facing gateway must NEVER reach the
    // worker's live socket.
    assert!(
        !groups.contains("fineco-ipc-live"),
        "gateway must NEVER join fineco-ipc-live, got `{groups}`"
    );
}

#[test]
fn private_worker_unit_holds_creds_has_network_and_no_db() {
    let lines = active_lines(&deploy_file("systemd/fineco-private-worker.service"));
    // The credential worker is fineco-worker — distinct from the store user.
    assert_eq!(
        effective(&lines, "User"),
        Some("fineco-worker"),
        "the private worker must run as fineco-worker"
    );
    // It reads ONLY its own credential env file (root:fineco-worker 0640).
    assert_eq!(
        effective(&lines, "EnvironmentFile"),
        Some("/etc/fineco/private-worker.env"),
        "the worker must load its credential env file"
    );
    // It needs the network (outbound to Fineco) — unlike the no-network store.
    assert_ne!(
        effective(&lines, "PrivateNetwork"),
        Some("true"),
        "the worker must NOT disable the network (it reaches Fineco)"
    );
    let families = effective(&lines, "RestrictAddressFamilies").expect("worker sets families");
    assert!(
        families.contains("AF_INET"),
        "the worker must allow INET for Fineco, got `{families}`"
    );
    // Egress pinning is the nft skuid layer, NOT systemd cgroup-BPF IPAddress*
    // (which may be unavailable in the unprivileged LXC).
    assert!(
        !lines.iter().any(|l| l.starts_with("IPAddress")),
        "the worker must not rely on systemd IPAddress* (egress is pinned by nftables)"
    );
    // It holds NO DB handle: no DB path, no StateDirectory.
    assert!(
        effective_env(&lines, "FINECO_DB_PATH").is_none(),
        "the worker must not open the DB"
    );
    assert!(
        effective(&lines, "StateDirectory").is_none(),
        "the worker must own no persistent state (the DB is the store's)"
    );
}

#[test]
fn tmpfiles_declares_the_three_setgid_socket_dirs() {
    // Each socket dir is setgid 2750 to its IPC group so the socket inherits the group;
    // owner-write only (no group write) so only the SERVING process creates/unlinks the
    // socket — group members merely connect. Group write would allow socket spoofing.
    let lines = active_lines(&deploy_file("tmpfiles.d/fineco-helper.conf"));
    let dir = |path: &str| -> String {
        lines
            .iter()
            .find(|l| l.starts_with('d') && l.contains(path))
            .unwrap_or_else(|| panic!("missing tmpfiles entry for {path}"))
            .clone()
    };
    for (path, owner, group) in [
        ("/run/fineco-helper ", "fineco-store", "fineco-ipc-store"),
        (
            "/run/fineco-helper-refresh",
            "fineco-store",
            "fineco-ipc-refresh",
        ),
        ("/run/fineco-worker", "fineco-worker", "fineco-ipc-live"),
    ] {
        let entry = dir(path);
        assert!(
            entry.contains("2750"),
            "{path} must be setgid 2750 (owner-write only — no group write): {entry}"
        );
        assert!(
            !entry.contains("2770"),
            "{path} must NOT be group-writable (2770): {entry}"
        );
        assert!(
            entry.contains(owner) && entry.contains(group),
            "{path} must be {owner}:{group}: {entry}"
        );
    }
}

#[test]
fn every_service_unit_suppresses_core_dumps() {
    // No core dumps anywhere: a dump could carry the Access JWT, the tunnel token,
    // cached private data, the SQLite DB, or a notifier secret out of a hardened
    // process. store/worker already had it; the rest are added here.
    for unit in [
        "fineco-gateway",
        "fineco-store-server",
        "fineco-private-worker",
        "cloudflared",
        "fineco-backup",
        "fineco-alert",
        "fineco-refresh-portfolio",
        "fineco-refresh-egress-set",
    ] {
        let lines = active_lines(&deploy_file(&format!("systemd/{unit}.service")));
        assert_eq!(
            effective(&lines, "LimitCORE"),
            Some("0"),
            "{unit}.service must set LimitCORE=0 (suppress core dumps)"
        );
    }
}

#[test]
fn firewall_sample_denies_by_default_inbound_and_outbound() {
    let lines = active_lines(&deploy_file("firewall/fineco-egress.nft"));
    // input/forward/output hooks must each default-drop (active rules only).
    let drops = lines.iter().filter(|l| l.contains("policy drop;")).count();
    assert!(
        drops >= 3,
        "firewall must default-drop input/forward/output, found {drops} active drop policies"
    );
}

#[test]
fn firewall_pins_the_private_worker_egress_before_the_broad_https_rule() {
    // M8 hard gate: the private-fineco-worker (uid fineco-worker) is host-pinned to
    // the resolved Fineco set + pinned DNS, and its catch-all deny+log MUST sit
    // before the broad tcp/443 allow — otherwise a compromised worker could
    // exfiltrate over the broad rule. This is the static (CI) half of the egress
    // gate; the privileged egress-deny E2E runs on the target host.
    let body = deploy_file("firewall/fineco-egress.nft");
    let lines = active_lines(&body);

    let worker_deny = lines
        .iter()
        .position(|l| l.contains("skuid \"fineco-worker\"") && l.ends_with("drop"))
        .expect("a uid-scoped private-worker egress deny must exist");
    let worker_https = lines
        .iter()
        .position(|l| {
            l.contains("skuid \"fineco-worker\"")
                && l.contains("@fineco_worker_v4")
                && l.contains("tcp dport 443 accept")
        })
        .expect("the worker https-to-Fineco-set allow must exist");
    let broad_443 = lines
        .iter()
        .position(|l| l.starts_with("tcp dport 443 accept"))
        .expect("the broad tcp/443 rule must exist");

    // Ordering: worker allow -> worker deny -> broad allow.
    assert!(
        worker_https < worker_deny,
        "the worker Fineco allow must precede its deny"
    );
    assert!(
        worker_deny < broad_443,
        "the worker egress deny must precede the broad tcp/443 allow (else it's an escape path)"
    );

    // The loopback escape: the worker deny must ALSO precede the broad output
    // `oif "lo" accept`, else a compromised worker could reach any local listener
    // (e.g. the gateway's 127.0.0.1 bind), bypassing the Fineco-IP pinning.
    let output_loopback = lines
        .iter()
        .position(|l| l.starts_with("oif \"lo\" accept"))
        .expect("the output loopback accept must exist");
    assert!(
        worker_deny < output_loopback,
        "the worker egress deny must precede the loopback accept (else loopback is an escape path)"
    );

    // The deny is the alert source and family-agnostic (no IPv6 escape).
    let deny = &lines[worker_deny];
    assert!(
        deny.contains("fineco-egress-deny private-worker"),
        "the worker deny must log the egress-deny alert prefix"
    );
    assert!(
        !deny.contains("ip daddr") && !deny.contains("ip6 daddr"),
        "the worker deny must be family-agnostic (close the IPv6 hole)"
    );

    // The named sets the timer populates must be declared (worker + pinned DNS,
    // both families).
    for set in [
        "fineco_worker_v4",
        "fineco_worker_v6",
        "fineco_dns_v4",
        "fineco_dns_v6",
    ] {
        assert!(
            body.contains(&format!("set {set}")),
            "missing nft set {set} for the worker egress allowlist"
        );
    }
}

#[test]
fn firewall_pins_the_gateway_egress_before_the_broad_https_rule() {
    // The internet-facing gateway (uid fineco-gateway) is pinned to its resolved
    // targets (CF JWKS + enrichment + ETF) so a compromised gateway can't exfiltrate
    // the cached private data it can read to an arbitrary host. Static (CI) half;
    // the live egress-deny verification runs on the target host.
    let body = deploy_file("firewall/fineco-egress.nft");
    let lines = active_lines(&body);
    let pos = |pred: &dyn Fn(&str) -> bool, what: &str| {
        lines
            .iter()
            .position(|l| pred(l))
            .unwrap_or_else(|| panic!("missing nft rule: {what}"))
    };

    let gw_loopback = pos(
        &|l| l.contains("skuid \"fineco-gateway\"") && l.contains("oif \"lo\" accept"),
        "gateway loopback accept",
    );
    let gw_https = pos(
        &|l| {
            l.contains("skuid \"fineco-gateway\"")
                && l.contains("@fineco_gateway_v4")
                && l.contains("tcp dport 443 accept")
        },
        "gateway https-to-target-set allow",
    );
    let gw_deny = pos(
        &|l| l.contains("fineco-egress-deny gateway"),
        "gateway egress deny",
    );
    let broad_443 = pos(
        &|l| l.starts_with("tcp dport 443 accept"),
        "broad tcp/443 allow",
    );

    // CRITICAL (else the cloudflared tunnel breaks): the gateway SERVES cloudflared
    // over IP loopback, so the loopback accept must precede the gateway deny —
    // otherwise the gateway's replies to cloudflared are dropped.
    assert!(
        gw_loopback < gw_deny,
        "the gateway loopback accept must precede its deny (or the tunnel dies)"
    );
    // There must be NO broad `ct state established accept` for the gateway: allowed
    // replies are covered by oif-lo + the dport-443-to-set rule, and a broad
    // established-accept would keep alive a connection to a de-allowlisted IP.
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("skuid \"fineco-gateway\"") && l.contains("established,related")),
        "the gateway block must not broadly accept established connections"
    );
    // The HTTPS-to-pinned-set allow precedes the deny; the deny precedes the broad
    // tcp/443 (else arbitrary egress is an escape path).
    assert!(
        gw_https < gw_deny,
        "gateway https allow must precede its deny"
    );
    assert!(
        gw_deny < broad_443,
        "the gateway egress deny must precede the broad tcp/443 allow"
    );

    // The IPv6 HTTPS allow + ALL four DNS allows (v4/v6, udp/tcp) must exist and
    // precede the deny — else an IPv6-only or DNS path is bricked fail-closed.
    for needle in [
        "skuid \"fineco-gateway\" ip6 daddr @fineco_gateway_v6 tcp dport 443 accept",
        "skuid \"fineco-gateway\" ip daddr @fineco_dns_v4 udp dport 53 accept",
        "skuid \"fineco-gateway\" ip daddr @fineco_dns_v4 tcp dport 53 accept",
        "skuid \"fineco-gateway\" ip6 daddr @fineco_dns_v6 udp dport 53 accept",
        "skuid \"fineco-gateway\" ip6 daddr @fineco_dns_v6 tcp dport 53 accept",
    ] {
        let at = pos(&|l| l.contains(needle), needle);
        assert!(
            at < gw_deny,
            "gateway rule `{needle}` must precede the deny"
        );
    }

    let deny = &lines[gw_deny];
    assert!(
        deny.contains("fineco-egress-deny gateway"),
        "the gateway deny must log the egress-deny alert prefix"
    );
    assert!(
        !deny.contains("ip daddr") && !deny.contains("ip6 daddr"),
        "the gateway deny must be family-agnostic (close the IPv6 hole)"
    );
    for set in ["fineco_gateway_v4", "fineco_gateway_v6"] {
        assert!(
            body.contains(&format!("set {set}")),
            "missing nft set {set} for the gateway egress allowlist"
        );
    }
}

#[test]
fn backup_script_encrypts_compresses_and_keeps_no_plaintext() {
    let script = deploy_file("backup/fineco-backup.sh");
    // age-encrypted to a PUBLIC recipient + gzip-compressed.
    assert!(
        script.contains("age -r") && script.contains("$RECIPIENT"),
        "the backup must age-encrypt to a public recipient"
    );
    assert!(script.contains("gzip"), "the backup must compress");
    // The plaintext copy is transient: a private mktemp dir removed on exit.
    assert!(
        script.contains("mktemp -d") && script.contains("trap 'rm -rf"),
        "the plaintext copy must live in a temp dir removed on exit"
    );
    // Tiered retention 7 daily / 8 weekly / 12 monthly (plan "Backup And Restore").
    for tier in ["daily\" 7", "weekly\" 8", "monthly\" 12"] {
        assert!(
            script.contains(&format!("prune \"$ROOT/{tier}")),
            "missing retention for {tier}"
        );
    }
    let timer = active_lines(&deploy_file("systemd/fineco-backup.timer"));
    assert!(
        timer.iter().any(|l| l.starts_with("OnCalendar=")),
        "the backup must be timer-driven"
    );
}

#[test]
fn restore_script_needs_the_offline_identity_and_will_not_overwrite() {
    let script = deploy_file("backup/fineco-restore.sh");
    // Decrypt with an age identity (the OFFLINE private key) — not a recipient.
    assert!(
        script.contains("age -d -i"),
        "restore must decrypt with the offline age identity"
    );
    assert!(script.contains("gunzip"), "restore must decompress");
    // Refuse to clobber an existing output (a restore must never destroy a live DB).
    assert!(
        script.contains("refusing to overwrite"),
        "restore must refuse to overwrite an existing target"
    );
}

#[test]
fn egress_set_refresh_is_atomic_fail_loud_and_timer_driven() {
    // The refresh replaces the sets in ONE atomic `nft -f` transaction (flush set +
    // add element), so in-flight packets never see an empty set (no deny window),
    // and it fails LOUDLY (no `|| true`) so an empty allow set can never be masked
    // by a green unit. On incomplete resolution it keeps the last-known-good sets.
    let script = deploy_file("firewall/fineco-refresh-egress-set.sh");
    assert!(
        script.contains("nft -f -"),
        "the refresh must apply one atomic nft transaction"
    );
    assert!(
        script.contains("flush set") && script.contains("add element"),
        "the atomic transaction must flush + repopulate each set"
    );
    assert!(
        !active_lines(&script).iter().any(|l| l.contains("|| true")),
        "the refresh must fail loudly — never swallow an nft error with `|| true`"
    );
    assert!(
        script.contains("last-known-good"),
        "an incomplete resolution must keep the last-known-good sets, not empty them"
    );
    assert!(
        script.contains("timeout"),
        "elements carry a timeout as a dead-timer backstop"
    );
    assert!(
        script.contains("private-api.finecobank.com"),
        "the refresh must resolve the fixed Fineco private-API host"
    );
    // It ALSO populates the gateway egress sets: the fixed public ETF CDN plus the
    // JWKS + enrichment hosts read from the gateway's OWN config at runtime (the
    // enrichment host is config-only — NEVER a literal in the script).
    assert!(
        script.contains("fineco_gateway_v4") && script.contains("fineco_gateway_v6"),
        "the refresh must populate the gateway egress sets"
    );
    assert!(
        script.contains("images.finecobank.com"),
        "the gateway set must include the fixed public ETF CDN"
    );
    assert!(
        script.contains("gateway_incomplete"),
        "EVERY gateway host must resolve before flushing the set — a partial \
         resolution (e.g. JWKS fails) must keep last-known-good, not drop a target"
    );
    assert!(
        script.contains("could not be parsed"),
        "a PRESENT-but-unparseable gateway host URL must fail closed (else a malformed \
         JWKS URL silently omits JWKS and the gateway can't authenticate)"
    );
    assert!(
        script.contains("[^[:space:]"),
        "the fail-closed must only trip on a NON-BLANK value — a blank VAR= means \
         'unset' (the gateway falls back to its default), so it must not fail there"
    );
    assert!(
        script.contains("worker_dns_ok") && script.contains("gateway_ok"),
        "worker/DNS and gateway sets must refresh INDEPENDENTLY — a gateway-host DNS \
         failure must not block the worker/DNS refresh (they would expire after 1h)"
    );
    assert!(
        script.contains("HTTPS/443 only"),
        "a non-443 port on a gateway target must fail closed (the allowlist is 443-only)"
    );
    assert!(
        script.contains("flush set %s %s fineco_gateway_v4"),
        "with NO gateway targets configured the gateway sets must be FLUSHED (emptied), \
         not left with stale elements from a prior configuration"
    );
    assert!(
        script.contains("FINECO_ACCESS_JWKS_URL")
            && script.contains("FINECO_ENRICHMENT_BASE")
            && script.contains("FINECO_ETF_URL"),
        "the gateway hosts (JWKS + enrichment + any ETF override) must be read from config"
    );
    assert!(
        script.contains("/etc/fineco/enrichment.env"),
        "the config-only enrichment host is read from enrichment.env at runtime"
    );
    // The host extractor must tolerate a quoted value (VAR="https://…") and drop an
    // explicit :port — else a normal env style silently omits a gateway target.
    assert!(
        script.contains("{0,1") && script.contains("[^/:"),
        "host_from_url must tolerate an optional quote ({{0,1}}) and strip an explicit :port"
    );
    // The timer populates on boot (the firewall's flush leaves the sets empty) and
    // refreshes periodically.
    let timer = active_lines(&deploy_file("systemd/fineco-refresh-egress-set.timer"));
    assert!(
        timer.iter().any(|l| l.starts_with("OnBootSec=")),
        "the egress-set timer must populate on boot"
    );
    assert!(
        timer.iter().any(|l| l.starts_with("OnUnitActiveSec=")),
        "the egress-set timer must refresh periodically"
    );
}

#[test]
fn alert_script_is_payload_free_and_notifier_agnostic() {
    // The live-refresh alerting (plan "Observability → Minimum alerts") must derive
    // every alert from a payload-free source and NEVER open the SQLite DB or forward
    // a value. The functional firing is proven in tests/alerting.rs; this guards the
    // script's shape so it cannot be silently widened.
    let script = deploy_file("alerting/fineco-alert.sh");
    // Never touches the DB (no path, no sqlite, no value read).
    for forbidden in [".sqlite", "/var/lib/fineco-helper", "fineco-history"] {
        assert!(
            !script.contains(forbidden),
            "the alert script must never read the SQLite DB (found {forbidden:?})"
        );
    }
    // Each named alert's payload-free source is present.
    for src in [
        "nft list chain inet fineco output", // egress deny counter
        "NRestarts",                         // worker restart loop
        "--cursor-file",                     // only NEW gateway audit lines
        "refresh_budget_exhausted",
        "auth_required",
        "refresh_circuit_open",
        "refresh_live_sensitive", // refresh spike
    ] {
        assert!(script.contains(src), "the alert script must scan {src:?}");
    }
    // Notifier-agnostic with a journald default; delivery is a configurable command.
    assert!(
        script.contains("FINECO_ALERT_COMMAND") && script.contains("logger -t fineco-alert"),
        "delivery must be a configurable command defaulting to journald (logger)"
    );
    // First run only seeds (no alert flood on install).
    assert!(
        script.contains("seeded state on first run"),
        "the first run must seed state and emit nothing"
    );
    // At-least-once: the cursor + counters advance via a STAGING copy committed
    // only after every delivery succeeds, so a broken notifier re-fires next run.
    assert!(
        script.contains("journal.cursor.stage") && script.contains("delivery_ok"),
        "the cursor/counters must be staged and committed only on full delivery"
    );
    assert!(
        script.contains("state NOT advanced"),
        "a failed delivery must decline to advance state (re-fire next run)"
    );
    // Defense-in-depth: refuse to run if the root-executed notifier config is
    // not root-owned / non-writable, then SOURCE a FIXED path (not systemd-imported,
    // not an env-overridable path), under an absolute interpreter.
    assert!(
        script.contains("must be root-owned and not group/other-writable"),
        "the script must reject a tamperable alert.env"
    );
    assert!(
        script.contains("CONFIG=/etc/fineco/alert.env") && script.contains(". \"$CONFIG\""),
        "the script must validate then source a FIXED config path"
    );
    assert!(
        script.lines().next() == Some("#!/bin/bash"),
        "the root alert script must use an absolute interpreter (no PATH-resolved env)"
    );
    // The notifier must NOT hold CAP_NET_ADMIN (needed only for the nft read): run
    // it with BOTH the bounding and ambient sets cleared (the root-exec rule pulls
    // caps from the bounding set, so clearing ambient alone is insufficient).
    assert!(
        script.contains("setpriv --bounding-set=-all --ambient-caps=-all"),
        "the notifier must run with the bounding + ambient cap sets cleared"
    );
}

#[test]
fn alert_unit_is_a_hardened_root_oneshot_and_timer_driven() {
    let unit = active_lines(&deploy_file("systemd/fineco-alert.service"));
    assert_eq!(
        effective(&unit, "Type"),
        Some("oneshot"),
        "the alert unit is a oneshot"
    );
    // alert.env must NOT be systemd-imported — that would load it (PATH/BASH_ENV)
    // into the root process before the script could validate it. The script reads
    // the fixed path itself after an ownership check (asserted above).
    assert!(
        !unit.iter().any(|l| l.starts_with("EnvironmentFile")),
        "alert.env must not be imported via systemd EnvironmentFile (script validates+sources it)"
    );
    // CAP_NET_ADMIN to read the nftables counter + CAP_SETPCAP to drop the bounding
    // set before running a notifier (the root-exec rule would otherwise re-grant the
    // notifier CAP_NET_ADMIN from the bounding set). Nothing else.
    assert_eq!(
        effective(&unit, "CapabilityBoundingSet"),
        Some("CAP_NET_ADMIN CAP_SETPCAP"),
        "the alert unit must be clamped to exactly CAP_NET_ADMIN + CAP_SETPCAP"
    );
    assert_eq!(
        effective(&unit, "StateDirectory"),
        Some("fineco-alert"),
        "per-run state must live in a systemd StateDirectory"
    );
    for (k, v) in REQUIRED_HARDENING {
        assert_eq!(
            effective(&unit, k),
            Some(*v),
            "the alert unit must set {k}={v}"
        );
    }
    let timer = active_lines(&deploy_file("systemd/fineco-alert.timer"));
    assert!(
        timer.iter().any(|l| l.starts_with("OnBootSec="))
            && timer.iter().any(|l| l.starts_with("OnUnitActiveSec=")),
        "the alert scan must run on boot and periodically"
    );
    // The timer must NOT Requires=/Wants= the service it triggers: that would pull
    // the oneshot in at enable/boot, and a non-zero exit (unreadable source / failed
    // notifier) could then fail the timer itself instead of retrying next tick.
    assert!(
        !timer
            .iter()
            .any(|l| l.starts_with("Requires=") || l.starts_with("Wants=")),
        "the alert timer must not Requires=/Wants= its service (it triggers it on elapse)"
    );
}

#[test]
fn no_timer_requires_the_service_it_triggers() {
    // A .timer already activates its same-named .service on elapse. A Requires=/Wants=
    // would also pull the oneshot in at enable/boot, so a transient non-zero exit
    // (an unreadable alert source, a backup hiccup, an egress-set resolver gap) could
    // leave the TIMER failed instead of just retrying on the next tick.
    for timer in [
        "fineco-alert.timer",
        "fineco-backup.timer",
        "fineco-refresh-egress-set.timer",
        "fineco-refresh-portfolio.timer",
    ] {
        let lines = active_lines(&deploy_file(&format!("systemd/{timer}")));
        assert!(
            !lines
                .iter()
                .any(|l| l.starts_with("Requires=") || l.starts_with("Wants=")),
            "{timer} must not Requires=/Wants= the service it triggers"
        );
    }
}

#[test]
fn refresh_portfolio_unit_is_a_hardened_socket_client_oneshot() {
    let lines = active_lines(&deploy_file("systemd/fineco-refresh-portfolio.service"));

    // Triggers the param-less portfolio refresh through the controller.
    assert_eq!(
        effective(&lines, "ExecStart"),
        Some("/usr/local/bin/fineco-helper refresh portfolio"),
        "must invoke the `refresh portfolio` subcommand"
    );
    assert_eq!(effective(&lines, "Type"), Some("oneshot"));

    // Runs as an ephemeral DynamicUser joined to ONLY the refresh group — never a
    // standing account (which would inherit that user's other groups: the gateway is
    // also in fineco-ipc-store + fineco-policy), and never root, store, or live.
    assert_eq!(
        effective(&lines, "DynamicUser"),
        Some("yes"),
        "an ephemeral least-privilege identity, not a standing account"
    );
    assert!(
        !lines.iter().any(|l| l.starts_with("User=")),
        "must not pin a standing User= (it would inherit that account's other groups)"
    );
    assert_eq!(
        effective(&lines, "SupplementaryGroups"),
        Some("fineco-ipc-refresh"),
        "the only standing group is refresh-control"
    );

    // A pure socket client: no credentials/DB, so no EnvironmentFile and no
    // capabilities, reachable only over AF_UNIX.
    assert!(
        effective_env(&lines, "FINECO_REFRESH_SOCKET").is_some(),
        "the refresh-control socket is set inline (not via a sourced EnvironmentFile)"
    );
    assert!(
        !lines.iter().any(|l| l.starts_with("EnvironmentFile")),
        "must not use EnvironmentFile (the M8 PATH/BASH_ENV-injection lesson)"
    );
    assert_eq!(
        effective(&lines, "CapabilityBoundingSet"),
        Some(""),
        "the trigger needs no capabilities"
    );
    assert_eq!(
        effective(&lines, "RestrictAddressFamilies"),
        Some("AF_UNIX"),
        "the trigger reaches the controller only over a Unix socket"
    );
    for (key, value) in [
        ("NoNewPrivileges", "true"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "true"),
        ("PrivateTmp", "true"),
        ("RestrictNamespaces", "true"),
    ] {
        assert_eq!(
            effective(&lines, key),
            Some(value),
            "refresh unit: effective `{key}` must be `{value}`"
        );
    }
    // It writes no files: no ReadWritePaths grant (ProtectSystem=strict => read-only).
    assert!(
        !lines.iter().any(|l| l.starts_with("ReadWritePaths")),
        "the trigger writes nothing; it needs no ReadWritePaths"
    );
    // A live refresh can take up to the client's 180s reply timeout, so the oneshot's
    // start timeout must EXCEED that — otherwise systemd's ~90s default would SIGKILL a
    // still-valid refresh before the subcommand's own clean fail-closed timeout.
    let start_timeout: u64 = effective(&lines, "TimeoutStartSec")
        .and_then(|v| v.parse().ok())
        .expect("TimeoutStartSec must be set to a plain seconds value");
    assert!(
        start_timeout > 180,
        "TimeoutStartSec ({start_timeout}) must exceed the client's 180s reply timeout"
    );
}

#[test]
fn refresh_portfolio_timer_fires_mon_to_sat_morning_rome_randomized() {
    let lines = active_lines(&deploy_file("systemd/fineco-refresh-portfolio.timer"));
    let on_calendar = effective(&lines, "OnCalendar").expect("OnCalendar must be set");
    assert!(
        on_calendar.contains("Mon..Sat"),
        "must run Mon-Sat (skip Sunday), got: {on_calendar}"
    );
    assert!(
        on_calendar.contains("06:00") && on_calendar.contains("Europe/Rome"),
        "must anchor at 06:00 Europe/Rome, got: {on_calendar}"
    );
    // The randomized delay spreads the fire time across the 06:00-08:00 window so the
    // unattended login is not a fixed, machine-looking timestamp.
    assert_eq!(
        effective(&lines, "RandomizedDelaySec"),
        Some("2h"),
        "must spread the fire time over the two-hour morning window"
    );
    // Must NOT be Persistent=: a catch-up run fires on activation subject only to
    // RandomizedDelaySec, i.e. a login OUTSIDE the 06:00-08:00 window (the fraud-
    // heuristic risk this unit exists to avoid). A skipped day waits for the next tick.
    assert!(
        effective(&lines, "Persistent") != Some("true"),
        "the timer must not be Persistent= — a catch-up run would log in outside the window"
    );
}

#[test]
fn notifier_hook_examples_are_placeholders_only() {
    // The committed notifier configs must carry only PLACEHOLDERS — never a real
    // token/password — and must keep the secret in the file (the hook contract), so
    // a filled-in copy is never accidentally committed.
    let cases = [
        ("alerting/examples/telegram.curl.example", "<BOT_TOKEN>"),
        ("alerting/examples/ntfy.curl.example", "<YOUR_NTFY_TOKEN>"),
        ("alerting/examples/msmtprc.example", "passwordeval"),
    ];
    for (path, placeholder) in cases {
        let body = deploy_file(path);
        assert!(
            body.contains(placeholder),
            "{path} must keep the {placeholder} placeholder"
        );
        // A real Telegram bot token is <digits>:<35+ base64url chars>. Reject one.
        assert!(
            !regex_lite_telegram_token(&body),
            "{path} appears to contain a REAL bot token — keep it a placeholder"
        );
    }
    // The README states the hook contract (stdin in, exit-0 = delivered, secret in a file).
    let readme = deploy_file("alerting/examples/README.md");
    for needle in ["stdin", "exit 0", "0600"] {
        assert!(
            readme.contains(needle),
            "the examples README must document the hook contract ({needle})"
        );
    }
}

/// True if `body` looks like it contains a real Telegram bot token
/// (`<8+ digits>:<35+ token chars>`), without pulling in a regex dependency. Also
/// catches the URL form `bot<digits>:<secret>` (e.g. inside a sendMessage URL) by
/// stripping a leading alpha prefix from the id segment.
fn regex_lite_telegram_token(body: &str) -> bool {
    body.split(|c: char| !(c.is_ascii_alphanumeric() || c == ':' || c == '_' || c == '-'))
        .any(|tok| {
            tok.split_once(':').is_some_and(|(id, secret)| {
                // Strip a `bot`/other alpha prefix so the URL form `bot<digits>:…`
                // still matches; a placeholder like `bot<BOT_TOKEN>` is split on the
                // `<`/`>` and never reaches here.
                let digits = id.trim_start_matches(|c: char| c.is_ascii_alphabetic());
                digits.len() >= 8
                    && digits.bytes().all(|b| b.is_ascii_digit())
                    && secret.len() >= 35
                    && secret
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            })
        })
}

#[test]
fn the_token_scanner_catches_url_and_bare_tokens() {
    // URL form (the actual leak shape in telegram.curl) + a bare token must be caught.
    assert!(regex_lite_telegram_token(
        "url = \"https://api.telegram.org/bot8123456789:AAHabcdefghijklmnopqrstuvwxyz0123456789X/sendMessage\""
    ));
    assert!(regex_lite_telegram_token(
        "8123456789:AAHabcdefghijklmnopqrstuvwxyz0123456789X"
    ));
    // Placeholders + ordinary config lines must NOT trip it.
    assert!(!regex_lite_telegram_token(
        "url = \"https://api.telegram.org/bot<BOT_TOKEN>/sendMessage\""
    ));
    assert!(!regex_lite_telegram_token("data = \"chat_id=8946379250\""));
    assert!(!regex_lite_telegram_token(
        "passwordeval \"cat /etc/fineco/smtp-password\""
    ));
}
