#!/usr/bin/env bash
#
# Daily encrypted backup of the SQLite store (plan "Backup And Restore"). Driven
# by fineco-backup.timer. Pipeline:
#
#   fineco-helper backup            # a consistent VACUUM INTO copy (online)
#   | gzip                          # compress
#   | age -r <PUBLIC recipient>     # encrypt — the PRIVATE key stays OFFLINE
#   -> daily/, plus weekly/ on Mon and monthly/ on the 1st
#   -> retention: 7 daily, 8 weekly, 12 monthly
#
# The plaintext copy exists only transiently inside a private mktemp dir and is
# removed on exit (trap). Run as the DB owner (fineco-store); the encrypted output
# is what leaves that boundary.
set -euo pipefail

DB="${FINECO_DB_PATH:-/var/lib/fineco-helper/fineco-history.sqlite}"
ROOT="${FINECO_BACKUP_DIR:-/var/backups/fineco-helper}"
BIN="${FINECO_HELPER_BIN:-/usr/local/bin/fineco-helper}"
# Your age PUBLIC recipient (age1...). Encryption needs only this; keep the
# matching private identity OFFLINE (used only at restore time).
RECIPIENT="${FINECO_BACKUP_AGE_RECIPIENT:?set FINECO_BACKUP_AGE_RECIPIENT to your age public key (age1...)}"

date="$(date -u +%F)" # YYYY-MM-DD (UTC)
dow="$(date -u +%u)"  # 1=Mon .. 7=Sun
dom="$(date -u +%d)"  # 01 .. 31

umask 0077
mkdir -p "$ROOT/daily" "$ROOT/weekly" "$ROOT/monthly"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
plain="$tmp/fineco-$date.sqlite"

# Online backup -> compress -> encrypt. The plaintext + the uncompressed copy
# never leave $tmp (0700, removed by the trap).
FINECO_DB_PATH="$DB" FINECO_BACKUP_OUT="$plain" "$BIN" backup

# Encrypt to a STAGING file in the destination dir (same filesystem), then `mv`
# atomically to the final name only after the whole `gzip | age` pipeline
# succeeds — so a mid-pipeline failure never leaves a truncated `.age` at the
# retained name. `set -o pipefail` makes a gzip/age failure abort the script.
out="$ROOT/daily/fineco-$date.sqlite.gz.age"
stage="$(mktemp "$ROOT/daily/.fineco-$date.XXXXXX")"
trap 'rm -rf "$tmp"; rm -f "$stage"' EXIT
gzip -c "$plain" | age -r "$RECIPIENT" -o "$stage"
mv -f "$stage" "$out"

# Promote to the weekly (Mon) / monthly (1st-of-month) tiers.
[[ "$dow" == "1" ]] && cp -a "$out" "$ROOT/weekly/"
[[ "$dom" == "01" ]] && cp -a "$out" "$ROOT/monthly/"

# Retention: keep the newest N encrypted backups in each tier. Sorted by the
# ISO-date filename (chronological), null-delimited so a dir path with spaces is
# safe; the `.age` names themselves are date-stamped (no spaces/newlines).
prune() { # dir keep
    find "$1" -maxdepth 1 -type f -name '*.sqlite.gz.age' -printf '%f\0' |
        sort -zr | tail -z -n "+$(($2 + 1))" |
        while IFS= read -r -d '' name; do rm -f -- "$1/$name"; done
}
prune "$ROOT/daily" 7
prune "$ROOT/weekly" 8
prune "$ROOT/monthly" 12
