# Admin reports

Admin → Reports (`/admin/reports`, API `GET /api/v1/admin/reports/{kind}?days=7|30|90&format=json|csv|xlsx`,
admin only).

| Report | Rows |
|---|---|
| `platform` | per day: scans by outcome, new findings by severity, new accounts |
| `modules` | per check: runs, could not run, findings by severity, false-positive groups (triage) |
| `scans` | every scan in the period, up to 5,000; site masked |
| `findings` | per check and severity: findings, groups, triage counts |
| `customers` | per customer account, masked: projects, scans, critical or high findings, last scan |
| `risk_trend` | per week: completed scans, average score, critical and high findings |

- **Masking is always on.** E-mail addresses (`a***@e***.com`) and sites (`s***.com`) are masked
  on screen and in every export. There is no unmasked export.
- **CSV.** UTF-8 with a BOM so Excel reads it. Cells that a spreadsheet would read as a formula
  (`= + - @`, tab, CR) are prefixed with `'` (CSV injection).
- **XLSX.** Built with the standard library (zip and XML, inline strings), with no dependency.
  Numbers stay numbers, and there are never formulas.
- **PDF.** "Print / save as PDF" uses the browser's print dialog on a print-friendly page: the
  navigation and buttons are hidden. There is no server PDF engine.
- **Audit.** Every CSV and XLSX export is audited as `report.exported`, with kind, format, days
  and row count.
- **Scheduled reports.** A weekly summary (Mondays) and a monthly summary (the 1st), both at
  06:05 UTC from api-jobs. They e-mail every admin counts and a link, never rows. Both are off
  until an admin switches them on, and each change is audited (`report.schedule_changed`).
  Migration 0021.
