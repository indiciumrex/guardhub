# GitHub App private key directory (ADR-0006)

Mounted read-only into the `api` and `api-jobs` containers at `/run/github-app`
(`GITHUB_APP_KEY_DIR`, default: this directory). In production it is
`/opt/guardhub/shared/github-app/` on the server, NOT this directory, and holds `app.pem`
(the GitHub App's private key, mode 0400, owned by uid 10001, the API image's user).

Never put a key here: this directory is in the repository. `.gitignore` refuses `*.pem` in it.
