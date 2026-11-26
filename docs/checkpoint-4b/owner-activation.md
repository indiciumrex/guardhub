# Sahip-hedef aktif test: açma adımları (kurucu onayıyla)

> **Durum: AÇILDI (2026-11-25 20:41Z, kurucunun "onayla"sıyla).** Kanıt geçti (2026-11-25
> 11:27Z, `kanit-plani.md`). Kapsam: yalnızca GuardHub'a ait, kanıtlanmış alan adları (yönetici
> güvenilir alan adları); bugün yalnızca `guardhub.dev`. Modüller: XSS, SQLi, açık yönlendirme,
> CORS, IDOR açık. **SSRF kapalı** (OOB toplayıcı yok). **Müşteri hedefleri kapalı** (ToS + rıza
> arayüzü + OOB + kurucunun "git"i gelmeden yolu yok). Karar kaydı: ADR-0008 §8 "Owner targets".

## Dört kilit ve bugünkü durumları (canlı, 2026-11-26)

| Kilit | Nerede | Bugün |
|---|---|---|
| 1. Kurucu onayı | API: `ACTIVE_TESTING_APPROVED` (`/opt/guardhub/shared/.env`) | `true` (2026-11-25 19:22Z) |
| 2. Tarayıcı anahtarı | scanner: `SCANNER_ACTIVE_ENABLED` (aynı dosya) | `true` (2026-11-25 19:22Z) |
| 3. Modüller | Yönetici → Modül Merkezi (her modül ayrı) | 5/6 açık (XSS, SQLi, redirect, CORS, IDOR); SSRF kapalı |
| 4. Durdurma anahtarı | Yönetici → Taramalar → Durdurma anahtarı | serbest, her an çekilebilir |

Hedef: `guardhub.dev` yönetici güvenilir alan adı, **active** (well_known, 2026-11-25 15:14Z;
jeton `/opt/guardhub/selfverify/guardhub-verify.txt` dosyasının 2. satırı). `sunizeka.net`
askıda (kanıt dosyası kalkmış).

## Açılış kaydı

- **Kilit 3 açılırken bir hata çıktı:** modül açma kontrolü aktif modüllerde Gate L dosyasına
  bakıyordu. Düzeltmesi PR #22: aktif modüller Gate M'e (`docs/accuracy-active`) bakar.
- **İlk gerçek aktif tarama:** `951e72db-02c2-4b2a-9c93-4381515c56b4`, 2026-11-25
  20:42:11–20:42:57Z. Sonuç:
  - 47 GET isteği, hepsi kapsam içinde;
  - nginx ile scanner kaydı birebir aynı;
  - 0 bulgu, kill switch çekilmedi.
  - Kanıt: `/opt/guardhub/proof/first-owner-scan-20261125T204211Z/`.
- **IDOR** açık ama iki test hesabının çerezi olmadan çalışmaz. Bugüne kadar çalışmadı.

## Adımlar (yapıldı; her biri denetim kaydına düştü; yeniden açmak gerekirse aynı sıra)

1. **guardhub.dev'i güvenilir alan adı yap (kurucu, yönetici paneli).** Yönetici → Güvenilir
   alan adları → `guardhub.dev` ekle → verilen jetonu iletin. Jeton sunucuda
   `/opt/guardhub/selfverify/guardhub-verify.txt` dosyasına **yeni bir satır** olarak eklenir
   (mevcut satır kalır; dosya herkese açık, sır değildir). Sonra panelde "doğrula".
   Durum `active` olmalı.
2. **Kilit 1 + 2 (sunucu, kurucunun açık onayıyla).** `/opt/guardhub/shared/.env` dosyasına:
   `ACTIVE_TESTING_APPROVED=true` ve `SCANNER_ACTIVE_ENABLED=true`. Sonra yalnızca etkin rengin
   `api` ve `scanner` servisleri yeniden oluşturulur (`up -d --no-deps`); A–K kapıları elle
   yeniden doğrulanır. Geri almak: iki satırı silip aynı yeniden oluşturma.
3. **Kilit 3 (kurucu, Modül Merkezi).** `active_xss`, `active_sqli`, `active_redirect`,
   `active_cors`, `active_idor` aç. `active_ssrf` kapalı kalır (API zaten OOB olmadan reddeder).
4. **Kilit 4:** durdurma anahtarı serbest olmalı (bugün serbest).
5. **İlk tarama (kurucu, Taramalar → "GuardHub'a ait bir sitede aktif tarama").** Engelleyen
   kilit listesi boş görünmeli. Hariç yollar varsayılan `/admin`, `/api`; onay kutusu → başlat.
   Tarama sırasında durdurma: aynı sayfada "Durdurma anahtarı".

## Her an durdurma / geri alma

- Panel: "Tüm aktif testleri şimdi durdur" (≤ 2 s, kanıtta 949 ms ölçüldü).
- Modülü kapatmak, `.env` satırlarını silmek: her biri tek başına yeni taramayı engeller.
- İstek günlüğü 30 gün saklanır (migration 0018), taramanın "ne gönderildi" kaydı panelde.

## Bilerek açık bırakılanlar

- IDOR, iki test hesabının çerezi verilmezse çalışmaz (sessizce atlanır). Çerezler tek
  kullanımlık Redis anahtarında 15 dk durur, tarayıcı okurken siler; hiçbir yerde saklanmaz.
- Her dağıtımda Gate F öz-taraması jeton dosyasına kendi satırını geçici ekler, sonra eski hâline
  getirir; güvenilir alan adı satırı silinmez.
