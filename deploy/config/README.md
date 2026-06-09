# Per-host config templates

Copy each `*.env.example` to its path under `/etc/fineco/`, drop the `.example`
suffix, fill in your values, and set the listed owner/mode. **None of these is
committed** — they hold (or gate) your secrets. The full walkthrough is
[`docs/SELF-HOSTING.md`](../../docs/SELF-HOSTING.md).

| Template | Install to | Owner / mode | Read by | Required? |
| --- | --- | --- | --- | --- |
| `private-worker.env.example` | `/etc/fineco/private-worker.env` | `root:fineco-worker` `0640` | private-worker | **yes** (live refresh) |
| `access.env.example` | `/etc/fineco/access.env` | `root:fineco-gateway` `0640` | gateway | **yes** (fail-closed) |
| `enrichment.env.example` | `/etc/fineco/enrichment.env` | `root:fineco-gateway` `0640` | gateway | optional (market tools) |
| `cloudflared.env.example` | `/etc/fineco/cloudflared.env` | `root:root` `0600` | cloudflared | **yes** (remote access) |
| `backup.env.example` | `/etc/fineco/backup.env` | `root:fineco-store` `0640` | backup timer (runs as `fineco-store`) | optional (encrypted backups) |
| `alert.env.example` | `/etc/fineco/alert.env` | `root:root` `0640` | alert timer (runs as `root`) | optional (alerting; journald default) |
| [`../policy.json`](../policy.json) | `/etc/fineco/policy.json` | `root:fineco-policy` `0640` | gateway + store-server | **yes** (capabilities) |

Install example (one file):

    install -m0640 -o root -g fineco-worker private-worker.env /etc/fineco/private-worker.env

The **enrichment host** and **all secrets** stay on the host only — never in the
repo, image, or git history.
