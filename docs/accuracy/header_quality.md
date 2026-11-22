# `header_quality` accuracy

Lab source revision `tree:scanner@d39590e02eab,corpus@b2826a9423d6`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 6 | 0 | 0 | 0 | 0 | 47 | 42 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `cookie_response_cacheable` | 1 | 0 | 0 |
| `coop_missing` | 1 | 0 | 0 |
| `csp_base_uri_missing` | 1 | 0 | 0 |
| `csp_object_src_unrestricted` | 1 | 0 | 0 |
| `csp_unsafe_eval` | 1 | 0 | 0 |
| `permissions_policy_missing` | 1 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (6)

- `hq-cache` / `cookie_response_cacheable` at `https://hq-cache.lab.test/#set-cookie=__Host-sid`: Oracle fetch of / (lab run 2026-11-22): Set-Cookie __Host-sid with Cache-Control 'public, max-age=600' and no private/no-store/no-cache (RFC 9111 §5.2.2: shared caches may store it).
- `hq-eval` / `csp_unsafe_eval` at `https://hq-eval.lab.test/`: Mozilla HTTP Observatory (@mdn/mdn-http-observatory 1.4.8, lab run 2026-11-22): content-security-policy result csp-implemented-with-unsafe-eval, policy.unsafeEval=true (clean.lab.test: false).
- `hq-nonce` / `csp_base_uri_missing` at `https://hq-nonce.lab.test/`: Google CSP Evaluator (csp_evaluator 1.1.8 checkMultipleMissingBaseUriDirective, lab run 2026-11-22): missing base-uri finding for the nonce policy (clean.lab.test: none).
- `hq-noperm` / `coop_missing` at `https://hq-noperm.lab.test/`: Oracle fetch of / (lab run 2026-11-22): HTML 200 without a Cross-Origin-Opener-Policy header (clean.lab.test sends one).
- `hq-noperm` / `permissions_policy_missing` at `https://hq-noperm.lab.test/`: Oracle fetch of / (guardhub-lab oracle, node fetch, lab run 2026-11-22): HTML 200 without a Permissions-Policy header (clean.lab.test sends one).
- `hq-object` / `csp_object_src_unrestricted` at `https://hq-object.lab.test/`: Mozilla HTTP Observatory (@mdn/mdn-http-observatory 1.4.8, lab run 2026-11-22): policy.unsafeObjects=true (clean.lab.test: false).

