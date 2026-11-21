# `subdomain_takeover` accuracy

Lab source revision `5c983db5731c`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 6 | 0 | 0 | 0 | 0 | 54 | 48 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `dangling_cname` | 1 | 0 | 0 |
| `unclaimed_resource` | 5 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (6)

- `st-azure` / `unclaimed_resource` at `CNAME app.azpos.st.lab.test`: dig CNAME app.azpos.st.lab.test -> azpos-app.azurewebsites.net; dig A azpos-app.azurewebsites.net -> NXDOMAIN.
- `st-bitbucket` / `unclaimed_resource` at `http://docs.bbpos.st.lab.test/`: CT answer is []; dig CNAME docs.bbpos.st.lab.test -> bbpos.bitbucket.io; curl -> 404 "Repository not found".
- `st-chain` / `unclaimed_resource` at `http://cdn.chainpos.st.lab.test/`: dig: cdn.chainpos -> edge.chainpos.st.lab.test -> chainpos-media.s3-website-eu-west-1.amazonaws.com; curl http://cdn.chainpos.st.lab.test/ -> 404 NoSuchBucket.
- `st-dangling` / `dangling_cname` at `CNAME old.dangpos.st.lab.test`: dig CNAME old.dangpos.st.lab.test -> site.gone-cdn.test; dig A site.gone-cdn.test -> NXDOMAIN; gone-cdn.test is not a listed provider, so low, not high.
- `st-s3` / `unclaimed_resource` at `http://assets.s3pos.st.lab.test/`: dig CNAME assets.s3pos.st.lab.test -> assets.s3pos.st.lab.test.s3.amazonaws.com; curl http://assets.s3pos.st.lab.test/ -> 404 NoSuchBucket "The specified bucket does not exist".
- `st-surge` / `unclaimed_resource` at `http://www.surgepos.st.lab.test/`: dig CNAME www.surgepos.st.lab.test -> surgepos.surge.sh; curl -> 404 "project not found".

