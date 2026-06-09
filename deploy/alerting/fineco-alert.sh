#!/bin/bash
#
# fineco-alert — wire the M8 live-refresh alerts (plan "Observability → Minimum
# alerts", scoped to live refresh) to a notifier. Driven by fineco-alert.timer
# (OnBoot + every few minutes). Install at /usr/local/libexec/fineco-alert.
#
# Each alert is derived ONLY from a payload-free source — see
# docs/LIVE-REFRESH-GATES.md for the full map:
#   - gateway audit journal  (budget exhausted / repeated LIVE-REFRESH auth_required /
#                             circuit opened / refresh spike)
#   - refresh one-shot journal (scheduled portfolio refresh failed — read on the same
#                             cursor as the gateway journal)
#   - nftables deny COUNTER  (private-worker egress deny)
#   - nftables deny COUNTER  (gateway egress deny — exfil attempt to a non-allowlisted host)
#   - systemd NRestarts      (private-worker restart loop)
# It NEVER opens the SQLite DB, holds no secret, and forwards only a one-line
# summary (alert TYPE + a COUNT + a timestamp) — never a raw journal line or a
# value.
#
# Delivery is notifier-agnostic: each fired alert is piped (one line on stdin) to
# $FINECO_ALERT_COMMAND from /etc/fineco/alert.env. The default sink is
# `logger -t fineco-alert` (journald). Wire your own channel (ntfy / email /
# webhook) by setting FINECO_ALERT_COMMAND there.
#
# CONFIG TRUST: the notifier is a ROOT-executed shell string, and config values
# (PATH/BASH_ENV/etc.) influence a root bash process — so the unit deliberately
# does NOT use systemd `EnvironmentFile` (that would import the file BEFORE any
# validation). Instead this script reads a FIXED path (`/etc/fineco/alert.env`,
# never an env override) and refuses to run unless it is root-owned and not
# group/other-writable, then sources it. The shebang is an absolute interpreter so
# a tampered PATH cannot redirect it.
#
# DELIVERY IS AT-LEAST-ONCE: the journald cursor and the counter baselines are
# advanced via a STAGING copy and committed only after every alert in the run is
# delivered AND every alert source read cleanly. A transient broken notifier or an
# unreadable source therefore re-fires next run rather than silently dropping a
# security alert; a genuine source/delivery failure exits non-zero (a failed unit,
# not a green timer with silently-disabled alerts).
#
# State (a seed marker + last-seen counters + a journald cursor) lives in the
# systemd StateDirectory /var/lib/fineco-alert so each run only considers NEW
# events; the FIRST run seeds the state and emits nothing (no flood on install).
#
# Runs as root: reading the nftables counter needs CAP_NET_ADMIN and the journal
# read needs privilege; the notifier may reach the network.
set -euo pipefail

# --- config: validate ownership of a FIXED path, then source it (see CONFIG TRUST
# above). GNU stat/find (the Linux target); transparently skipped where `stat -c`
# is absent (e.g. a dev macOS run) or the file is absent (defaults + the process
# environment apply). ---
CONFIG=/etc/fineco/alert.env
if [ -e "$CONFIG" ] && stat -c %U "$CONFIG" >/dev/null 2>&1; then
    if [ "$(stat -c %U "$CONFIG")" != root ] \
        || [ -n "$(find "$CONFIG" -perm /022 2>/dev/null || true)" ]; then
        echo "fineco-alert: refusing to run — $CONFIG must be root-owned and not group/other-writable" >&2
        exit 1
    fi
    . "$CONFIG"
fi

STATE_DIR="${STATE_DIRECTORY:-/var/lib/fineco-alert}"
GATEWAY_UNIT="fineco-gateway"
WORKER_UNIT="fineco-private-worker"
# The scheduled-refresh one-shot: its journal is read alongside the gateway's (one
# shared cursor) so a failed unattended refresh — which runs via the controller, NOT
# the gateway, so it leaves no gateway-audit line — is still surfaced.
REFRESH_UNIT="fineco-refresh-portfolio.service"
# The three live-refresh MCP tools — the audit lines whose error codes these
# alerts key on (so a cached-read auth error never trips the live-refresh alerts).
REFRESH_TOOL='tool["= :]+private_[a-z]+_refresh_live_sensitive'

# Thresholds: alert when the count of NEW matching events in this run's window
# reaches N. Override any of these in /etc/fineco/alert.env.
EGRESS_MIN="${FINECO_ALERT_EGRESS_MIN:-1}"
GATEWAY_EGRESS_MIN="${FINECO_ALERT_GATEWAY_EGRESS_MIN:-1}"
AUTHFAIL_MIN="${FINECO_ALERT_AUTHFAIL_MIN:-3}"
SPIKE_MIN="${FINECO_ALERT_SPIKE_MIN:-6}"
RESTART_MIN="${FINECO_ALERT_RESTART_MIN:-3}"
ALERT_COMMAND="${FINECO_ALERT_COMMAND:-logger -t fineco-alert}"

mkdir -p "$STATE_DIR"
seeded="$STATE_DIR/seeded"
cursor="$STATE_DIR/journal.cursor"
stage="$STATE_DIR/journal.cursor.stage"
egress_state="$STATE_DIR/egress-counter"
gateway_egress_state="$STATE_DIR/gateway-egress-counter"
restart_state="$STATE_DIR/worker-nrestarts"

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# Run the notifier with CAP_NET_ADMIN DROPPED. The script needs that capability
# only to read the nftables counter; the notifier (curl/mail/…) must not have it.
# Because the script runs as root (euid 0), clearing the ambient set is NOT enough
# — the kernel's "root file caps = all-ones" exec rule re-grants caps from the
# BOUNDING set. So drop the bounding set too (needs CAP_SETPCAP, granted to the
# unit): `setpriv --bounding-set=-all --ambient-caps=-all` leaves the notifier
# capability-less. setpriv is util-linux (always on the Debian target); probe once
# and fall back to a direct run where it is unavailable/unusable (e.g. dev macOS,
# or a context without CAP_SETPCAP such as the test harness).
NOTIFY_RUNNER='sh -c'
if command -v setpriv >/dev/null 2>&1 \
    && setpriv --bounding-set=-all --ambient-caps=-all true >/dev/null 2>&1; then
    NOTIFY_RUNNER='setpriv --bounding-set=-all --ambient-caps=-all sh -c'
fi

# Deliver one payload-free line to the notifier. A delivery FAILURE is recorded
# (NOT fatal) so the run still attempts every alert and then declines to advance
# state — the missed events re-fire next run.
# NOTE: $ALERT_COMMAND runs as a process, so any secret placed DIRECTLY in it would
# be visible in argv (/proc/<pid>/cmdline) to local users. alert.env.example tells
# the operator to keep notifier secrets in a file the notifier reads (curl
# --config / -H @file / netrc, or msmtp's own config), never inline.
delivery_ok=1
notify() {
    if ! printf 'fineco-alert: %s at %s\n' "$1" "$(now)" | $NOTIFY_RUNNER "$ALERT_COMMAND"; then
        delivery_ok=0
        echo "fineco-alert: notifier delivery failed for: $1" >&2
    fi
}

# --- counter-based sources (each tracked for read success, so an unreadable
# source fails loud instead of masking as 0) ---
# The private-worker egress deny rule's packet counter (the reliable egress-deny
# signal in an unprivileged LXC; its `log` line does not surface in journald). An
# nft FAILURE (ruleset not applied, chain renamed, lost CAP_NET_ADMIN) must not be
# silently read as 0 — that would mask real denies.
# Extract the packet counter for ONE named egress-deny rule from the (already read)
# chain text — scoped to the rule label so the worker + gateway counters never
# conflate (there are now two deny rules). Empty if that rule is absent.
egress_counter_for() { # rule_label
    printf '%s\n' "$egress_raw" \
        | awk -v r="fineco-egress-deny $1" 'index($0, r) { for (i = 1; i <= NF; i++) if ($i == "packets") print $(i + 1) }' \
        | head -n1
}
egress_ok=1 egress_now=0 gateway_egress_ok=1 gateway_egress_now=0
if egress_raw="$(nft list chain inet fineco output 2>/dev/null)"; then
    egress_now="$(egress_counter_for "private-worker")"
    if [ -z "$egress_now" ]; then
        # nft ok but the deny rule is absent (egress not pinned / chain changed): do
        # NOT read that as "0 denies" — flag the source unreadable (unprotected).
        echo "fineco-alert: the worker fineco-egress-deny rule is absent — egress not pinned? — alert source UNWIRED" >&2
        egress_ok=0
        egress_now=0
    fi
    gateway_egress_now="$(egress_counter_for "gateway")"
    if [ -z "$gateway_egress_now" ]; then
        echo "fineco-alert: the gateway fineco-egress-deny rule is absent — gateway egress not pinned? — alert source UNWIRED" >&2
        gateway_egress_ok=0
        gateway_egress_now=0
    fi
else
    echo "fineco-alert: cannot read the nftables egress counter — alert sources UNWIRED" >&2
    egress_ok=0
    egress_now=0
    gateway_egress_ok=0
    gateway_egress_now=0
fi

# The worker's restart count. A systemctl read failure (cannot reach systemd, or
# the unit/property is unavailable) yields an empty value; do NOT record that as 0
# — it would overwrite the baseline and suppress restart-loop alerts. NRestarts is
# always a number for a loaded unit, so empty == unreadable.
restart_ok=1
if restart_now="$(systemctl show -p NRestarts --value "$WORKER_UNIT" 2>/dev/null)" \
    && [ -n "$restart_now" ]; then
    :
else
    echo "fineco-alert: cannot read the $WORKER_UNIT restart count — alert source UNWIRED" >&2
    restart_ok=0
    restart_now=0
fi

# --- first run: seed the cursor + counters, emit nothing (no flood on install) ---
# A dedicated SEED MARKER (not the cursor file's existence) gates this, so a seed
# where journald wrote no cursor (e.g. an empty journal) still records as seeded.
# But do NOT seed (or mark seeded) when a counter source was unreadable: recording
# a bogus 0 baseline would fire a false delta on the next good read. Fail loud and
# retry next run instead.
if [ ! -f "$seeded" ]; then
    if [ "$egress_ok" -ne 1 ] || [ "$gateway_egress_ok" -ne 1 ] || [ "$restart_ok" -ne 1 ]; then
        echo "fineco-alert: cannot seed — a counter source is unreadable; retrying next run" >&2
        exit 1
    fi
    # The journal seed must also fail loud: a swallowed read error would mark seeded
    # WITHOUT a cursor, and the next run would then read from the start and fire
    # alerts for historical audit entries. (An empty journal is exit 0 — not an
    # error — so this only trips on a genuine read failure.)
    if ! journalctl -u "$GATEWAY_UNIT" -u "$REFRESH_UNIT" -o cat --cursor-file="$cursor" >/dev/null 2>&1; then
        echo "fineco-alert: cannot seed — the $GATEWAY_UNIT/$REFRESH_UNIT journal is unreadable; retrying next run" >&2
        exit 1
    fi
    printf '%s\n' "$egress_now" >"$egress_state"
    printf '%s\n' "$gateway_egress_now" >"$gateway_egress_state"
    printf '%s\n' "$restart_now" >"$restart_state"
    : >"$seeded"
    echo "fineco-alert: seeded state on first run; no alerts emitted" >&2
    exit 0
fi

# --- gateway audit + refresh one-shot journals: read NEW lines via a STAGING cursor
# (committed only after every alert in the run is delivered). With NO cursor yet (the
# seed ran before the units logged anything), read from the START so the first audit
# events are preserved, not skipped. A real read error flags the source unreadable
# but does NOT exit early — the journal-independent counter alerts below still run;
# only the final commit is gated. ---
journal_ok=1
new=""
rm -f "$stage"
[ -s "$cursor" ] && cp "$cursor" "$stage"
if new="$(journalctl -u "$GATEWAY_UNIT" -u "$REFRESH_UNIT" -o cat --cursor-file="$stage" 2>/dev/null)"; then
    :
else
    echo "fineco-alert: cannot read the $GATEWAY_UNIT/$REFRESH_UNIT journal — alert source UNWIRED" >&2
    journal_ok=0
    new=""
fi

count() { # $1=ERE -> number of matching NEW audit lines (0 if none)
    if [ -z "$new" ]; then printf 0; return; fi
    printf '%s\n' "$new" | grep -c -E -- "$1" || true
}
# Repeated LIVE-REFRESH auth failures only: a line must be BOTH a refresh-tool
# audit line AND carry error_code auth_required (a cached-read auth error, were
# one ever emitted, must not trip this).
count_refresh_authfail() {
    if [ -z "$new" ]; then printf 0; return; fi
    printf '%s\n' "$new" | grep -E -- "$REFRESH_TOOL" \
        | grep -c -E -- 'error_code["= :]+auth_required' || true
}

budget="$(count 'error_code["= :]+refresh_budget_exhausted')"
authfail="$(count_refresh_authfail)"
circuit="$(count 'error_code["= :]+refresh_circuit_open')"
spike="$(count "$REFRESH_TOOL")"
# The scheduled-refresh one-shot prints `fineco-helper: refresh failed: …` on any
# failure (SCA, timeout, a gate denial) before exiting non-zero. Threshold 1: a
# once-a-day unattended refresh failing even once is worth a ping (the day's refresh
# did not happen), unlike the manual-refresh noise the auth/spike thresholds damp.
refresh_fail="$(count 'fineco-helper: refresh failed')"

if [ "$budget" -ge 1 ]; then
    notify "live-refresh budget exhausted ($budget event(s))"
fi
if [ "$authfail" -ge "$AUTHFAIL_MIN" ]; then
    notify "repeated Fineco live-refresh auth failures ($authfail in window)"
fi
if [ "$circuit" -ge 1 ]; then
    notify "refresh circuit breaker opened ($circuit event(s))"
fi
if [ "$spike" -ge "$SPIKE_MIN" ]; then
    notify "live-refresh spike ($spike refreshes in window)"
fi
if [ "$refresh_fail" -ge 1 ]; then
    notify "scheduled portfolio refresh failed ($refresh_fail in window)"
fi

# --- counter-based alerts: independent of the journal, so they still fire when the
# journal read failed above (only the commit is gated on full success). ---
egress_last="$(cat "$egress_state" 2>/dev/null || echo 0)"
[ -n "$egress_last" ] || egress_last=0
# A reboot or `nft -f` reapply resets the deny counter below the saved baseline;
# treat the post-reset value itself as the delta (a negative diff would silently
# miss the denies that occurred since the reset).
if [ "$egress_now" -lt "$egress_last" ]; then
    egress_delta="$egress_now"
else
    egress_delta=$((egress_now - egress_last))
fi
if [ "$egress_ok" -eq 1 ] && [ "$egress_delta" -gt 0 ] && [ "$egress_delta" -ge "$EGRESS_MIN" ]; then
    notify "egress deny on private worker (counter +$egress_delta)"
fi

# The GATEWAY egress deny — a compromised internet-facing gateway attempting to
# exfiltrate cached private data to a non-allowlisted host. Same reset-aware delta.
if [ ! -f "$gateway_egress_state" ] && [ "$gateway_egress_ok" -eq 1 ]; then
    # New counter source on an ALREADY-SEEDED install (an upgrade adds the gateway
    # source after the one-time seed ran): seed its baseline ONCE, immediately AND
    # persistently (NOT gated on delivery) — so a later failed-delivery run can't
    # re-reset it (which would lose denies in that window), and pre-existing denies
    # don't fire a one-time false alert. Only when the source read cleanly.
    printf '%s\n' "$gateway_egress_now" >"$gateway_egress_state"
fi
gateway_egress_last="$(cat "$gateway_egress_state" 2>/dev/null || echo 0)"
[ -n "$gateway_egress_last" ] || gateway_egress_last=0
if [ "$gateway_egress_now" -lt "$gateway_egress_last" ]; then
    gateway_egress_delta="$gateway_egress_now"
else
    gateway_egress_delta=$((gateway_egress_now - gateway_egress_last))
fi
if [ "$gateway_egress_ok" -eq 1 ] && [ "$gateway_egress_delta" -gt 0 ] && [ "$gateway_egress_delta" -ge "$GATEWAY_EGRESS_MIN" ]; then
    notify "egress deny on gateway (counter +$gateway_egress_delta)"
fi

restart_last="$(cat "$restart_state" 2>/dev/null || echo 0)"
[ -n "$restart_last" ] || restart_last=0
# NRestarts resets to 0 on reboot / unit reload while the baseline persists; treat
# the post-reset value as the delta.
if [ "$restart_now" -lt "$restart_last" ]; then
    restart_delta="$restart_now"
else
    restart_delta=$((restart_now - restart_last))
fi
if [ "$restart_ok" -eq 1 ] && [ "$restart_delta" -ge "$RESTART_MIN" ]; then
    notify "private worker restart loop (NRestarts +$restart_delta)"
fi

# --- commit: advance each source's baseline INDEPENDENTLY (so a persistently
# broken source does not make the OTHER sources' alerts re-fire every run). A
# failed DELIVERY advances nothing (re-fire all). Any unreadable source or failed
# delivery exits non-zero — a failed unit, not a silent green timer. ---
fail=0
if [ "$delivery_ok" -eq 1 ]; then
    if [ "$journal_ok" -eq 1 ]; then
        [ -f "$stage" ] && mv -f "$stage" "$cursor"
    else
        rm -f "$stage"
        fail=1
    fi
    if [ "$egress_ok" -eq 1 ]; then printf '%s\n' "$egress_now" >"$egress_state"; else fail=1; fi
    if [ "$gateway_egress_ok" -eq 1 ]; then printf '%s\n' "$gateway_egress_now" >"$gateway_egress_state"; else fail=1; fi
    if [ "$restart_ok" -eq 1 ]; then printf '%s\n' "$restart_now" >"$restart_state"; else fail=1; fi
else
    rm -f "$stage"
    fail=1
fi
if [ "$fail" -ne 0 ]; then
    echo "fineco-alert: an alert source was unreadable or a delivery failed; affected state NOT advanced (re-fires next run)" >&2
    exit 1
fi
