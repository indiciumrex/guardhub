# Admin operational alerts

Admin → Alerts (`/admin/alerts`, API `/api/v1/admin/alerts…`, admin only). api-jobs evaluates the
rules every minute (`evaluate_ops_alerts`).

| Rule | Measures | Default |
|---|---|---|
| `critical_finding` | critical findings recorded in the window | 1 in 60 min, no escalation |
| `scan_failures` | scans that failed in the window | 5 in 30 min, escalate after 60 min |
| `worker_offline` | minutes without a scanner reading the job queue | 5 min, escalate after 30 min |
| `api_errors` | API 5xx responses in the window (Redis per-minute counter) | 20 in 15 min, escalate after 60 min |

- **One alert per rule.** While a condition holds there is one unresolved alert for it, updated
  on every check. When the condition clears, the alert resolves on its own. An admin can
  acknowledge an alert, or resolve it by hand: if the condition still holds, a new alert opens.
- **Channels.**
  - In-app is always on.
  - E-mail goes to every admin once, when an alert opens, unless the rule's e-mail is off or the
    rule is muted (1 h, 4 h or 24 h).
  - A failed mail is recorded on the alert and is never retried in a loop.
- **Escalation.** If nobody acknowledged an open alert within the rule's escalation time, one
  more e-mail is sent.
- **Content.** Mails carry the alert, the count, the threshold and a link only: no customer
  targets, findings or secrets. Texts are in `notifications.json` (`opsAlert`), en and tr.
- **Audit.** Every action is audited: `ops_alert.opened`, `ops_alert.acknowledged`,
  `ops_alert.resolved`, `ops_alert_rule.changed`, `ops_alert_rule.muted` and
  `ops_alert_rule.unmuted`.
- **Limitation.** The evaluator runs in api-jobs. If api-jobs itself is down, no alert can fire.
  The deploy gates (E-health) and the overview still show it.
