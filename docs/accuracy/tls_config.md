# `tls_config` accuracy

Lab source revision `c3afef35c824`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 9 | 0 | 0 | 0 | 0 | 80 | 74 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `cert_weak_key` | 1 | 0 | 0 |
| `chain_incomplete` | 1 | 0 | 0 |
| `no_forward_secrecy` | 1 | 0 | 0 |
| `tls13_unsupported` | 3 | 0 | 0 |
| `weak_cipher_3des` | 1 | 0 | 0 |
| `weak_cipher_insecure` | 2 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (9)

- `tls-3des` / `tls13_unsupported` at `tls-3des.lab.test:443`: Served with MaxVersion TLS 1.2.
- `tls-3des` / `weak_cipher_3des` at `tls-3des.lab.test:443`: labtls verify (full crypto/tls handshake): accepted TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA.
- `tls-nochain` / `chain_incomplete` at `tls-nochain.lab.test:443`: Only the leaf is served (openssl: 1 certificate, 'unable to verify the first certificate'); it names its issuer's AIA URL.
- `tls-nopfs` / `no_forward_secrecy` at `tls-nopfs.lab.test:443`: openssl: -cipher ECDHE:DHE refused, kRSA accepted (AES256-GCM-SHA384).
- `tls-nopfs` / `tls13_unsupported` at `tls-nopfs.lab.test:443`: openssl -tls1_3: refused (ssl_protocols TLSv1.2).
- `tls-rc4` / `tls13_unsupported` at `tls-rc4.lab.test:443`: Served with MaxVersion TLS 1.2.
- `tls-rc4` / `weak_cipher_insecure` at `tls-rc4.lab.test:443`: labtls verify (full crypto/tls handshake): accepted TLS_RSA_WITH_RC4_128_SHA (RC4, RFC 7465).
- `tls-rsa1024` / `cert_weak_key` at `tls-rsa1024.lab.test:443`: openssl x509: 'Public-Key: (1024 bit)'.
- `tls-weak` / `weak_cipher_insecure` at `tls-weak.lab.test:443`: openssl -cipher eNULL:aNULL: accepted ECDHE-ECDSA-NULL-SHA (no encryption).

