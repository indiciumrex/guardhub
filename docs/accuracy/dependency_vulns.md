# `dependency_vulns` accuracy

Lab source revision `709c7f0ecbd3`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 92.6% | 25 | 0 | 0 | 2 | 0 | 11 | 4 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `vulnerable_dependency_high` | 13 | 0 | 2 |
| `vulnerable_dependency_low` | 1 | 0 | 0 |
| `vulnerable_dependency_medium` | 4 | 0 | 0 |
| `vulnerable_dependency_no_fix` | 1 | 0 | 0 |
| `vulnerable_dev_dependency` | 6 | 0 | 0 |

## False positives (0)

None.

## False negatives (2)

- `rp-deps-traps` / `vulnerable_dependency_high` at `https://github.com/lab/rp-deps-traps/blob/HEAD/vendor/legacy/requirements.txt#pyyaml` (outside the declared scope): osv-scanner v2.2.4: pyyaml@5.3 has 2 advisory group(s), max rating CRITICAL; lowest version fixing all: 5.4; outside the declared scope: vendored directories are skipped
- `rp-deps-traps` / `vulnerable_dependency_high` at `https://github.com/lab/rp-deps-traps/blob/HEAD/yarn.lock#lodash` (outside the declared scope): osv-scanner v2.2.4: lodash@4.17.15 has 5 advisory group(s), max rating HIGH; lowest version fixing all: 4.18.0; outside the declared scope: yarn.lock is not supported yet

## True positives (25)

- `rp-npm` / `vulnerable_dependency_high` at `https://github.com/lab/rp-npm/blob/HEAD/package-lock.json#lodash`: osv-scanner v2.2.4: lodash@4.17.15 has 5 advisory group(s), max rating HIGH; lowest version fixing all: 4.18.0
- `rp-npm` / `vulnerable_dependency_high` at `https://github.com/lab/rp-npm/blob/HEAD/package-lock.json#minimist`: osv-scanner v2.2.4: minimist@1.2.5 has 1 advisory group(s), max rating CRITICAL; lowest version fixing all: 1.2.6
- `rp-npm` / `vulnerable_dependency_high` at `https://github.com/lab/rp-npm/blob/HEAD/package-lock.json#node-fetch`: osv-scanner v2.2.4: node-fetch@2.6.0 has 2 advisory group(s), max rating HIGH; lowest version fixing all: 2.6.7
- `rp-npm` / `vulnerable_dependency_low` at `https://github.com/lab/rp-npm/blob/HEAD/package-lock.json#cookie`: osv-scanner v2.2.4: cookie@0.6.0 has 1 advisory group(s), max rating LOW; lowest version fixing all: 0.7.0
- `rp-npm` / `vulnerable_dependency_medium` at `https://github.com/lab/rp-npm/blob/HEAD/package-lock.json#follow-redirects`: osv-scanner v2.2.4: follow-redirects@1.15.5 has 2 advisory group(s), max rating MODERATE; lowest version fixing all: 1.16.0
- `rp-npm` / `vulnerable_dependency_no_fix` at `https://github.com/lab/rp-npm/blob/HEAD/package-lock.json#request`: osv-scanner v2.2.4: request@2.88.2 has 1 advisory group(s), max rating MODERATE (no fixed version)
- `rp-npm` / `vulnerable_dev_dependency` at `https://github.com/lab/rp-npm/blob/HEAD/package-lock.json#minimatch`: osv-scanner v2.2.4: minimatch@3.0.4 has 4 advisory group(s), max rating HIGH, development dependency; lowest version fixing all: 3.1.4
- `rp-npm-v1` / `vulnerable_dependency_high` at `https://github.com/lab/rp-npm-v1/blob/HEAD/package-lock.json#handlebars`: osv-scanner v2.2.4: handlebars@4.5.2 has 15 advisory group(s), max rating CRITICAL; lowest version fixing all: 4.7.10
- `rp-npm-v1` / `vulnerable_dependency_high` at `https://github.com/lab/rp-npm-v1/blob/HEAD/package-lock.json#minimist`: osv-scanner v2.2.4: minimist@1.2.0 has 2 advisory group(s), max rating CRITICAL; lowest version fixing all: 1.2.6
- `rp-npm-v1` / `vulnerable_dependency_medium` at `https://github.com/lab/rp-npm-v1/blob/HEAD/package-lock.json#jquery`: osv-scanner v2.2.4: jquery@3.4.1 has 2 advisory group(s), max rating MODERATE; lowest version fixing all: 3.5.0
- `rp-npm-v1` / `vulnerable_dev_dependency` at `https://github.com/lab/rp-npm-v1/blob/HEAD/package-lock.json#debug`: osv-scanner v2.2.4: debug@2.6.8 has 2 advisory group(s), max rating HIGH, development dependency; lowest version fixing all: 2.6.9
- `rp-pip` / `vulnerable_dependency_high` at `https://github.com/lab/rp-pip/blob/HEAD/requirements.txt#ecdsa`: osv-scanner v2.2.4: ecdsa@0.19.0 has 2 advisory group(s), max rating HIGH; lowest version fixing all: 0.19.2
- `rp-pip` / `vulnerable_dependency_high` at `https://github.com/lab/rp-pip/blob/HEAD/requirements.txt#pyyaml`: osv-scanner v2.2.4: pyyaml@5.3 has 2 advisory group(s), max rating CRITICAL; lowest version fixing all: 5.4
- `rp-pip` / `vulnerable_dependency_high` at `https://github.com/lab/rp-pip/blob/HEAD/requirements.txt#requests`: osv-scanner v2.2.4: requests@2.19.0 has 5 advisory group(s), max rating HIGH; lowest version fixing all: 2.33.0
- `rp-pip` / `vulnerable_dependency_high` at `https://github.com/lab/rp-pip/blob/HEAD/requirements.txt#urllib3`: osv-scanner v2.2.4: urllib3@1.26.4 has 11 advisory group(s), max rating HIGH; lowest version fixing all: 2.8.0
- `rp-pip` / `vulnerable_dependency_medium` at `https://github.com/lab/rp-pip/blob/HEAD/requirements.txt#idna`: osv-scanner v2.2.4: idna@3.10 has 1 advisory group(s), max rating MODERATE; lowest version fixing all: 3.15
- `rp-pip` / `vulnerable_dependency_medium` at `https://github.com/lab/rp-pip/blob/HEAD/requirements.txt#jinja2`: osv-scanner v2.2.4: jinja2@2.11.2 has 5 advisory group(s), max rating MODERATE; lowest version fixing all: 3.1.6
- `rp-pip` / `vulnerable_dev_dependency` at `https://github.com/lab/rp-pip/blob/HEAD/requirements-dev.txt#pytest`: osv-scanner v2.2.4: pytest@8.3.3 has 1 advisory group(s), max rating MODERATE, development dependency; lowest version fixing all: 9.0.3
- `rp-pipfile` / `vulnerable_dependency_high` at `https://github.com/lab/rp-pipfile/blob/HEAD/Pipfile.lock#flask`: osv-scanner v2.2.4: flask@0.12 has 4 advisory group(s), max rating HIGH; lowest version fixing all: 3.1.3
- `rp-pipfile` / `vulnerable_dev_dependency` at `https://github.com/lab/rp-pipfile/blob/HEAD/Pipfile.lock#pytest`: osv-scanner v2.2.4: pytest@8.3.3 has 1 advisory group(s), max rating MODERATE, development dependency; lowest version fixing all: 9.0.3
- `rp-poetry` / `vulnerable_dependency_high` at `https://github.com/lab/rp-poetry/blob/HEAD/poetry.lock#pillow`: osv-scanner v2.2.4: pillow@9.0.0 has 54 advisory group(s), max rating CRITICAL; lowest version fixing all: 13.0.0
- `rp-poetry` / `vulnerable_dev_dependency` at `https://github.com/lab/rp-poetry/blob/HEAD/poetry.lock#ipython`: osv-scanner v2.2.4: ipython@8.0.0 has 2 advisory group(s), max rating HIGH, development dependency; lowest version fixing all: 8.10.0
- `rp-uv` / `vulnerable_dependency_high` at `https://github.com/lab/rp-uv/blob/HEAD/uv.lock#anyio`: osv-scanner v2.2.4: anyio@4.4.0 has 2 advisory group(s), max rating CRITICAL; lowest version fixing all: 4.14.2
- `rp-uv` / `vulnerable_dependency_high` at `https://github.com/lab/rp-uv/blob/HEAD/uv.lock#starlette`: osv-scanner v2.2.4: starlette@0.27.0 has 7 advisory group(s), max rating HIGH; lowest version fixing all: 1.3.1
- `rp-uv` / `vulnerable_dev_dependency` at `https://github.com/lab/rp-uv/blob/HEAD/uv.lock#black`: osv-scanner v2.2.4: black@22.3.0 has 4 advisory group(s), max rating CRITICAL, development dependency; lowest version fixing all: 26.10.1

