# Users & sessions (simple)

Admin → Users (`/admin/users`, API `/api/v1/admin/people…`). There are two roles, customer and
admin. The data boundary stays in the database (RLS). A full role matrix (RBAC) is deferred.

- **Disable / enable an account.** Disabling:
  - ends every session at once;
  - refuses sign-in (`403 account_disabled`, only after the right password, so it cannot be used
    to probe accounts);
  - stops the account's API keys;
  - holds its scheduled scans.

  An admin can never disable themselves or the last active admin. Audited as `user.disabled` and
  `user.enabled`. Migration 0024.
- **Sessions.** Full (two-factor) sessions are recorded in a Redis hash per account: issued,
  expires, keyed IP hash and a coarse browser/OS label, never the full user agent. Admins can end
  one session or all of them; this uses the existing per-session revocation. Audited as
  `user.sessions_ended`.
- **Failed sign-ins.** Wrong passwords and wrong two-factor codes come from the audit log
  (`auth.login_failed`, `auth.totp_failed`): per account over 24 h, plus the latest 100 with the
  keyed IP hash.
- **Admin invitations.**
  - The link is `ghi_` plus 32 random bytes. Only its keyed hash is stored, and it is shown once
    to the inviting admin, who sends it through a trusted channel.
  - It is valid for 72 h.
  - It makes an account an admin only when that exact e-mail is signed in with two-factor and
    accepts it.
  - The session is reissued with the new role. A used, revoked or expired link answers
    `404 invite_invalid`.
  - Audited as `admin_invite.created`, `admin_invite.accepted`, `admin_invite.revoked` and
    `user.role_changed`.
- **MFA.** Two-factor is already required for every account (`full_session`). The console shows
  each account's status. There is deliberately no "reset two-factor" button: it would let a
  stolen password take over an account.

Known limit: role and disabled state are protected in code (admin-only routes, system context),
not by a database trigger. A trigger would also block the operator promotion CLI; that is a
follow-up.

## Two-factor recovery (2026-11-26)

- **Recovery codes.** Ten single-use codes (`xxxxx-xxxxx`, about 49 bits each) are created when
  two-factor sign-in is first set up and shown once. Only keyed hashes are stored (migration
  0026). At sign-in, a code replaces the authenticator code once, under the same rate limit
  (5 tries per 5 minutes). Making new codes needs a current authenticator code and voids the old
  ones. Audited as `auth.recovery_code_used` and `auth.recovery_codes_regenerated`.
- **Reset by another admin.** It is never available for yourself. The acting admin confirms with
  their own current authenticator code (replay-protected), so a stolen session cookie is not
  enough. The reset:
  - clears the account's two-factor setup;
  - deletes its recovery codes;
  - ends every session.

  The account must then sign in with its password and set up two-factor again. Audited as
  `user.two_factor_reset`, with the reason.
- **DB guard (migration 0025).** `users.role`, `disabled_at` and `disabled_by` change only in an
  admin or system context, or from a maintenance connection that is not the application role. The
  operator promotion CLI runs in the system context and keeps working. This closes the "known
  limit" above.
