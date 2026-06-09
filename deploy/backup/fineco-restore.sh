#!/usr/bin/env bash
#
# Restore a fineco-helper backup (the monthly restore drill — plan "Backup And
# Restore"). Reverses fineco-backup.sh:
#
#   age -d -i <OFFLINE private identity> <backup.sqlite.gz.age> | gunzip > out.sqlite
#
# The age private identity is kept OFFLINE — provide it only for the drill, on a
# clean/recovery host, never stored on the production CT. Refuses to overwrite the
# output so a restore can never clobber a live DB.
#
#   fineco-restore.sh <backup.sqlite.gz.age> <out.sqlite> [age-identity-file]
set -euo pipefail

src="${1:?usage: fineco-restore.sh <backup.sqlite.gz.age> <out.sqlite> [age-identity]}"
out="${2:?usage: fineco-restore.sh <backup.sqlite.gz.age> <out.sqlite> [age-identity]}"
identity="${3:-${FINECO_BACKUP_AGE_IDENTITY:?provide the age identity (private key) file}}"

[[ -e "$out" ]] && {
    echo "refusing to overwrite existing $out" >&2
    exit 1
}

umask 0077
# Decrypt+decompress to a STAGING file in the destination dir, then `mv`
# atomically into place only after the whole pipeline succeeds — so a mid-stream
# age/gunzip failure (pipefail aborts) never leaves a partial SQLite file at $out
# that a retry would then refuse to overwrite, or that could be mistaken for valid.
outdir="$(dirname -- "$out")"
stage="$(mktemp "$outdir/.fineco-restore.XXXXXX")"
trap 'rm -f "$stage"' EXIT
age -d -i "$identity" "$src" | gunzip -c >"$stage"
mv -f "$stage" "$out"

echo "restored $out"
echo "verify: open it with the binary's readiness path, e.g."
echo "  FINECO_DB_PATH=$out FINECO_QUERY_SOCKET=/tmp/r.sock FINECO_POLICY_PATH=<policy> \\"
echo "    fineco-helper store-server &  # then a portfolio_get_freshness over the socket"
