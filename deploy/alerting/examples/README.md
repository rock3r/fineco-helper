# Alert notifier hooks

The live-refresh alerting ([`deploy/alerting/fineco-alert.sh`](../fineco-alert.sh))
delivers a fired alert by piping **one payload-free line** on stdin to
`sh -c "$FINECO_ALERT_COMMAND"` (from `/etc/fineco/alert.env`). This directory has
ready-to-adapt notifier configs.

## The hook contract

- **Input:** one line on **stdin** — `fineco-alert: <type> (<count>) at <UTC>`. Type
  + count + timestamp only; **never a value, price, or account identifier**.
- **Success = exit 0.** A non-zero exit marks the delivery failed: the alert is
  **re-fired on the next scan** (at-least-once), so a flaky channel never silently
  drops a security alert. Always make HTTP notifiers fail closed (`curl -f`). The
  examples also send the notifier's **stdout to `/dev/null`** (`curl … -o /dev/null`)
  so a chatty API response (which can echo your message + account name back) stays
  out of the alert journal; only its exit code matters.
- **Privilege:** the command runs as root but with **all capabilities dropped**
  (`setpriv --bounding-set=-all --ambient-caps=-all`), and may use the network.
- **Secrets live in a FILE, never in `FINECO_ALERT_COMMAND`.** The command string
  is visible in process listings (`ps`, `/proc/<pid>/cmdline`); a token there would
  defeat `alert.env`'s mode. Put the token in a `0600 root:root` file the notifier
  reads (`curl --config`, `-H @file`, `--netrc`, or msmtp's own config).

## Examples (pick one)

| Channel | Config file (install `0600 root:root`) | `FINECO_ALERT_COMMAND` |
| --- | --- | --- |
| **Telegram** | [`telegram.curl.example`](telegram.curl.example) → `/etc/fineco/telegram.curl` | `curl -fsS -o /dev/null --config /etc/fineco/telegram.curl --data-urlencode text@-` |
| **ntfy** | [`ntfy.curl.example`](ntfy.curl.example) → `/etc/fineco/ntfy.curl` | `curl -fsS -o /dev/null --config /etc/fineco/ntfy.curl -d @-` |
| **Email (SMTP)** | [`msmtprc.example`](msmtprc.example) → `/etc/msmtprc` (+ `apt install msmtp-mta`) | `mail -s "fineco-helper alert" you@example.com` |
| journald (default) | — | `logger -t fineco-alert` |

Then set `FINECO_ALERT_COMMAND` in `/etc/fineco/alert.env` (`0640 root:root`) and:

    systemctl start fineco-alert.service        # one scan; should finish clean (sources alert.env itself)
    # smoke-test delivery directly: source alert.env (not in your shell yet), then run the notifier:
    ( set -a; . /etc/fineco/alert.env; set +a
      printf 'fineco-alert: test at %s\n' "$(date -u +%FT%TZ)" | sh -c "$FINECO_ALERT_COMMAND" )

The full walkthrough (incl. Telegram bot setup) is in
[`docs/SELF-HOSTING.md`](../../../docs/SELF-HOSTING.md#alerting-notifications).
