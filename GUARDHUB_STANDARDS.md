# GuardHub — Dizin ve Standartlar (DIVINE_STANDARDS.md)

> **Amaç:** Bu belge GuardHub projesinin tek referans kaynağıdır (single source of truth).
> Hem yazılım ekipleri hem de AI agent'lar bu belgeyi okuyarak projeyi anlar, katkı yapar ve
> sürdürür. Her kural **net, gerekçeli ve uygulanabilir** olacak şekilde yazılmıştır.
>
> - **Ürün:** GuardHub — güvenlik uzmanı olmayan kurucular için sade, sürekli güvenlik bekçisi.
> - **Şirket:** HKSolutions · **Domain:** `guardhub.dev`
> - **Doküman sürümü:** 1.1 · Son güncelleme: 2026-11-16
> - **Durum:** Kuruluş / MVP öncesi mimari

---

## 0. Bu belge nasıl okunur

| Okuyucu | Nereden başlamalı |
|---|---|
| Yeni insan geliştirici | §1 → §2 → §4 → §6 → kendi servisinin §7'deki standartları |
| AI agent (kod yazan) | §2 (ilkeler) → §12 (agent protokolü) → ilgili servisin §7 bölümü → §10 (test) |
| Ürün / arayüz / yönetim | §1 → §3 → §8 (ürün altyapısı ve admin) → §11 (yol haritası) |
| Güvenlik gözden geçirmesi | §9 (güvenlik ve etik) |

**Altın kural:** Bir değişiklik bu belgedeki bir kurala aykırıysa, ya kuralı uygula ya da
önce bu belgeyi güncelleyen bir öneri sun. Belge ile kod çeliştiğinde **belge kazanır**;
kod belgeye uydurulur.

---

## 1. Vizyon ve kapsam

### 1.1 Tek cümlelik tanım
GuardHub, bir kurucunun canlı uygulamasının adresini girmesiyle, en yüksek sinyalli ve
gerçekten istismar edilen güvenlik açıklarını **sade dilde** tespit eden, sürekli izleyen ve
düzeltme yolunu gösteren bir SaaS'tır.

### 1.2 Kime hizmet eder
- AI ile / hızla üretilmiş ("vibe-coded") SaaS kuran, güvenlik uzmanı olmayan kurucular.
- 1-50 kişilik yazılım ekipleri, ajanslar, freelance geliştiriciler.

### 1.3 Ne değildir (kapsam dışı)
- Kurumsal AppSec paketi değil (Snyk/Wiz'in yerini almaz).
- LLM/prompt-injection güvenliği değil (ayrı, kalabalık bir pazar).
- Aktif sızma testi / saldırı aracı değil. **Yalnızca izinli, zarar vermeyen kontroller.**

### 1.4 Değer döngüsü
`Gir → Gör → Düzelt → Kanıtla`
Kullanıcı adresi girer, sonucu sade dilde görür, çözümü uygular, güven sayfasıyla müşterisine kanıtlar.

---

## 2. Temel ilkeler (teams + AI agents için bağlayıcı)

Bu ilkeler her karar ve her satır kod için geçerlidir.

1. **Sadelik > kapsam.** Her özellik bir yarayı kapatmalı. Şüphedeysen ekleme.
2. **Sade dil zorunludur.** Kullanıcıya gösterilen hiçbir bulgu ham CVE/stack-trace olamaz.
   Format her zaman: *ne açık + neden önemli + nasıl düzeltilir*.
3. **Zarar verme (do-no-harm).** Tarama motoru hiçbir zaman hedefe yük bindiren, veri bozan
   veya hizmet kesen istek atmaz. Varsayılan: pasif ve hız-sınırlı.
4. **İzin esastır.** Yalnızca kullanıcının sahipliğini/erişimini doğruladığı hedefler taranır (§9.2).
5. **Dogfooding.** Bir güvenlik ürünü kusursuz güvenli olmalı. Kendi kurallarımızı kendi
   altyapımıza uygularız.
6. **Deterministik ve açıklanabilir.** Aynı girdi → aynı bulgu. Her bulgu, onu üreten kurala
   ve kanıta (delil) izlenebilir olmalı.
7. **Agent-dostu kod.** Dosya ve fonksiyon isimleri niyeti anlatır; her modülün başında ne
   yaptığını söyleyen kısa bir açıklama bulunur; "sihirli" örtük davranış yoktur.
8. **Küçük, geri alınabilir değişiklikler.** Büyük PR yerine küçük, test edilmiş adımlar.
9. **Gizlilik.** Müşteri tarama verisi hassastır; en az veri topla, şifrele, erişimi logla (§9).
10. **Altyapı şimdi, UI/özellik sonra.** Veri modeli ve arayüzler geleceği öngörür (admin, AI,
    modül bayrakları, geçmiş); ağır özellikler fazlara yayılır ki hiçbir şey yeniden yazılmasın.

---

## 3. Üst düzey mimari

```
                         ┌─────────────────────────────┐
                         │        Next.js (web)         │
                         │ landing · dashboard · admin  │
                         │ scan · trust · user area     │
                         └───────────────┬─────────────┘
                                         │ HTTPS / REST
                         ┌───────────────▼─────────────┐
                         │      API (FastAPI · Python)  │
                         │ auth · projeler · orkestr.   │
                         │ bulgu · billing · admin      │
                         │ modül bayrakları · AI seam   │
                         │ öz-izleme · güven sayfası     │
                         └───────┬───────────────┬──────┘
                                 │               │
                   enqueue job   │               │  read/write
                                 ▼               ▼
                         ┌───────────────┐  ┌──────────────┐
                         │  Redis (queue │  │ PostgreSQL   │
                         │  + rate-limit)│  │ (kalıcı veri)│
                         └───────┬───────┘  └──────────────┘
                                 │ dequeue
                                 ▼
                         ┌─────────────────────────────┐
                         │   Scanner (Go · çok-uçlu)    │
                         │  eşzamanlı prob havuzu       │
                         │  check registry · delil top. │
                         └─────────────────────────────┘

        (opsiyonel, anahtar girilince)  AIProvider seam → zenginleştirme
```

**Rol dağılımı:**
- **FastAPI (Python)** — kullanıcı/oturum, proje yönetimi, tarama orkestrasyonu, bulguların
  sade dile çevrilmesi, billing, admin, modül bayrakları, AI seam, öz-izleme, güven sayfası.
- **Scanner (Go)** — asıl ağ işi. Tek bir tarama yüzlerce uç noktayı **eşzamanlı** yoklar;
  Go'nun goroutine + worker-pool modeli bu yüksek hacimli, I/O-ağırlıklı işte Python'dan
  verimlidir. Go servisi kuralları çalıştırır, **delil** toplar.
- **Redis** — tarama kuyruğu, dağıtık rate-limit, kısa ömürlü durum.
- **PostgreSQL** — kullanıcılar, projeler, taramalar, bulgular, modül bayrakları, abonelik, sağlık.
- **Next.js** — tüm kullanıcı arayüzü, admin paneli ve public güven sayfası.

**Neden iki dil:** Orkestrasyon ve iş mantığı Python'da hızlı ve okunabilir; ham eşzamanlı
tarama Go'da verimli. Sınır nettir: Python **ne taranacağına** karar verir, Go **tarar**.

---

## 4. Teknoloji yığını (kesin liste)

| Katman | Seçim | Neden |
|---|---|---|
| API / orkestrasyon | Python 3.12+ · FastAPI · Pydantic v2 | async, zengin güvenlik ekosistemi, hız |
| Tarayıcı işçiler | Go 1.22+ | yüksek eşzamanlılık, çok-uçlu ağ yoklama |
| Kuyruk / cache | Redis 7+ | iş kuyruğu, rate-limit, ephemeral durum |
| Veritabanı | PostgreSQL 16+ | ilişkisel, Row-Level Security, dayanıklı |
| Arka plan işleri | Arq (Python→Redis) + Go consumer | Python işleri tetikler, Go ağır işi çeker |
| Frontend | Next.js 14+ (App Router) · Tailwind | modern, SSR güven sayfası, admin, tek dil FE |
| Kimlik | FastAPI + JWT + TOTP 2FA + roller | standart; admin/kullanıcı rol ayrımı |
| Ödeme | Stripe (veya TR için iyzico/PayTR) | abonelik, dunning |
| Gözlemleme | OpenTelemetry + Sentry + structured logs | izleme ve hata takibi |
| Yerelleştirme | next-intl (web) + ortak çeviri kataloğu | 9 dil desteği (bkz. §7.5) |
| AI (opsiyonel) | `AIProvider` seam · sağlayıcı-bağımsız | anahtar girilince aktif (bkz. §8.3) |
| Dağıtım | Docker + Compose (MVP) → container platform | taşınabilir, self-host opsiyonu |

**Kural:** Bu listeye yeni bir runtime/dil eklemek bu belgede gerekçelendirilmeden yapılamaz.
Kütüphane eklemek serbesttir ama `deps` gerekçesi PR açıklamasında belirtilir.

---

## 5. Repo dizin haritası (monorepo)

```
guardhub/
├── GUARDHUB_STANDARDS.md          # bu belge — tek referans
├── README.md                      # hızlı başlangıç
├── docker-compose.yml             # yerel tüm servisler
├── .env.example                   # örnek ortam değişkenleri (gerçek sır YOK)
│
├── apps/
│   ├── api/                       # FastAPI — orkestrasyon beyni (Python)
│   │   ├── guardhub_api/
│   │   │   ├── main.py            # uygulama girişi
│   │   │   ├── config.py          # ayarlar (env'den, Pydantic Settings)
│   │   │   ├── db/                # SQLAlchemy modelleri + migration (alembic)
│   │   │   ├── auth/              # kayıt, login, JWT, 2FA, roller
│   │   │   ├── projects/          # proje CRUD + hedef doğrulama
│   │   │   ├── scans/             # tarama tetikleme, durum, sonuç, karşılaştırma
│   │   │   ├── findings/          # bulgu modeli + sade dile çeviri
│   │   │   ├── trust/             # güven sayfası üretimi
│   │   │   ├── billing/           # abonelik, dunning
│   │   │   ├── admin/             # modül bayrakları, kullanıcı/sistem yönetimi
│   │   │   ├── modules/           # modül kayıt defteri (feature flags)
│   │   │   ├── ai/                # AIProvider seam (no-op → anahtarla aktif)
│   │   │   ├── health/            # öz-izleme / sistem sağlığı (AI'sız)
│   │   │   └── common/            # hatalar, logging, yardımcılar
│   │   ├── tests/
│   │   └── pyproject.toml
│   │
│   ├── scanner/                   # Go — çok-uçlu tarama motoru
│   │   ├── cmd/scanner/main.go    # worker girişi (Redis'ten iş çeker)
│   │   ├── internal/
│   │   │   ├── pool/              # worker-pool + eşzamanlılık kontrolü
│   │   │   ├── checks/            # her kontrol ayrı dosya (registry)
│   │   │   │   ├── registry.go    # tüm kontrollerin kaydı
│   │   │   │   ├── exposed_env.go # .env / .git / sır sızıntısı
│   │   │   │   ├── headers.go     # CSP / HSTS / güvenlik başlıkları
│   │   │   │   ├── tls.go         # sertifika / TLS
│   │   │   │   ├── open_admin.go  # açık admin / debug uçları
│   │   │   │   └── ...            # yeni kontroller buraya
│   │   │   ├── probe/             # güvenli HTTP istemcisi (rate-limit, timeout)
│   │   │   ├── evidence/          # delil toplama ve normalize
│   │   │   ├── progress/          # canlı tarama ilerlemesi (API'ye yayın)
│   │   │   └── queue/             # Redis consumer + sonuç yayını
│   │   ├── go.mod
│   │   └── tests/
│   │
│   └── web/                       # Next.js — tüm UI + güven sayfası + admin
│       ├── app/
│       │   ├── (marketing)/       # landing (marka: GuardHub + HKSolutions)
│       │   ├── scan/              # ücretsiz tek seferlik tarama (kanca)
│       │   ├── dashboard/         # taramalar, bulgular, karşılaştırma
│       │   ├── account/           # kullanıcı alanı (projeler, geçmiş, abonelik)
│       │   ├── admin/             # yönetim paneli (rol + 2FA korumalı)
│       │   └── trust/[slug]/      # public güven sayfası (SSR, çok dilli)
│       ├── components/
│       │   └── brand/             # logo, "Powered by HKSolutions"
│       └── package.json
│
├── packages/
│   └── shared/                    # çapraz sözleşmeler (schema/types)
│       ├── finding.schema.json    # bulgu şeması — Python+Go+TS ortak kaynağı
│       ├── check-ids.json         # kontrol kimlikleri kataloğu
│       ├── brand/                 # marka varlıkları (tek kaynak)
│       └── i18n/<locale>/         # çeviri kataloğu (9 dil)
│
├── ops/
│   ├── migrations/                # veritabanı migration'ları
│   ├── ci/                        # CI pipeline tanımları
│   └── runbooks/                  # operasyon kılavuzları
│
└── docs/
    ├── architecture.md            # derin mimari notlar
    ├── checks/                    # her kontrolün ayrıntılı dokümanı
    └── adr/                       # mimari karar kayıtları (ADR)
```

**Dizin ilkesi:** Bir özellik, sahibi olan tek bir dizine ait olur. Çapraz veri (bulgu şeması,
kontrol kimlikleri, marka, çeviriler) `packages/shared` içinde **tek kaynaktan** tanımlanır.

---

## 6. Veri modeli (çekirdek varlıklar)

```
User         (id, email, password_hash, totp_secret, role[user|admin],
              locale, created_at)
Project      (id, user_id, name, target_url, ownership_verified_at, created_at)
Scan         (id, project_id, status[queued|running|done|failed], score,
              started_at, finished_at, trigger[manual|scheduled|ci])
Finding      (id, scan_id, check_id, severity[critical|high|medium|low|info],
              title_key, plain_summary, fix_guidance, evidence_ref, status[open|fixed|ignored])
Evidence     (id, finding_id, kind, redacted_payload, captured_at)   # hassas → maskeli/şifreli
ScanDiff     (türetilmiş)  # iki tarama arası: yeni / düzelen / regresyon
TrustPage    (id, project_id, slug, is_public, snapshot_at)
Subscription (id, user_id, plan[free|pro|agency], status, current_period_end)

# Yönetim ve altyapı
Module       (id, key, name, category, enabled_global, min_plan[free|pro|agency],
              rolled_out_at)                                         # feature flag
AIConfig     (id, provider, api_key_ref, enabled, updated_by, updated_at)  # anahtar şifreli
HealthCheck  (id, module_key, status[ok|degraded|down], error_rate, latency_ms, checked_at)
AuditLog     (id, actor, action, target, at)                        # değişmez (append-only)

# Repo bağlama (ADR-0006)
GitHubInstallation (id, user_id, installation_id, account_login, account_type,
                    created_at, revoked_at)   # token SAKLANMAZ; tarama başına daraltılmış token
Project.kind [site|repo] + repo_id, repo_full_name, github_installation_id
```

**Kurallar:**
- `Finding.plain_summary` ve `fix_guidance` her zaman sade dilde ve çeviri-anahtarlı (i18n).
- `Evidence.redacted_payload` asla ham sır içermez; bulunan sır **maskelenir** (ör. son 4 hane).
- `AIConfig.api_key_ref` şifreli referanstır; ham anahtar veritabanında açık durmaz.
- PostgreSQL **Row-Level Security**: kullanıcı yalnızca kendi `user_id`'sine bağlı satırları görür;
  admin rolü yönetim kapsamını görür.
- `AuditLog` değişmezdir; her hassas işlem (login, modül aç/kapat, AI anahtarı değişimi) loglanır.

---

## 7. Servis bazlı kodlama standartları

### 7.1 API (Python / FastAPI) — `apps/api`
- **Tip güvenliği:** Her girdi/çıktı Pydantic v2 modeli. `Any` yasağı (gerekçesiz).
- **Katmanlar:** `router → service → repository`. Router HTTP bilir, service iş mantığı bilir,
  repository veritabanı bilir. Katman atlanmaz.
- **Async:** Tüm I/O `async`. Bloklayan çağrı yasak; gerekirse thread-pool.
- **Hatalar:** Tek bir hata hiyerarşisi (`common/errors.py`). HTTP'ye çeviri tek yerde.
- **Sır yönetimi:** Sır yalnızca ortam değişkeninden; koda gömmek **yasak** (CI bunu tarar).
- **Format/lint:** `ruff` + `mypy` zorunlu; CI geçmeden merge yok.
- **Her modül** başında 2-3 satır docstring: ne yapar, ne yapmaz.

### 7.2 Scanner (Go) — `apps/scanner`
- **Eşzamanlılık:** Çok-uçlu yoklama **worker-pool** ile. Sınırsız goroutine yasak;
  havuz boyutu ve toplam eşzamanlı istek **yapılandırılabilir ve sınırlı** olur.
- **Güvenli istemci (`probe/`):** her istekte timeout, retry-with-backoff, per-host rate-limit,
  `User-Agent: GuardHub-Scanner`, redirect sınırı. Hedefe yük bindirmek yasaktır.
- **Canlı ilerleme (`progress/`):** tarayıcı, hangi kontrolün çalıştığını adım adım API'ye yayınlar
  ki kullanıcı "ne taranıyor" görsün (bkz. §8.5 görünür tarama).
- **Kontroller (`checks/`):** her kontrol tek dosya, `Check` arayüzünü uygular:
  `ID() string`, `Run(ctx, target) ([]Finding, error)`. Yeni kontrol = yeni dosya + registry'e kayıt.
  Kontroller **saf ve deterministik**; durum paylaşmaz.
- **Delil (`evidence/`):** her bulgu, onu doğrulayan maskelenmiş delille döner. Delilsiz bulgu yok.
- **Bağlam (`context.Context`):** her iş iptal edilebilir; tarama zaman aşımına uyar.
- **Format/lint:** `gofmt` + `go vet` + `golangci-lint` zorunlu.
- **Go'nun sınırı:** Scanner **sade dil üretmez**; ham teknik bulgu + delil döndürür.
  Sade dile çeviri API katmanında (`findings/`) yapılır.

### 7.3 Web (Next.js / TypeScript) — `apps/web`
- **Tek dil FE:** TypeScript `strict`. `any` yasak.
- **Sunucu/istemci ayrımı:** veri çekme Server Component'te; etkileşim Client Component'te.
- **Görünür tarama:** tarama ekranı, kontrollerin canlı ilerlemesini gösterir (hangi kontrol şu an çalışıyor).
- **Güven sayfası SSR:** `trust/[slug]` public, SEO-dostu, ziyaretçinin dilinde; hassas veri sızdırmaz.
- **Marka:** her ekranda GuardHub logosu + "Powered by HKSolutions" (bkz. §8.1).
- **Tasarım:** sade, kurumsal, erişilebilir; bulgular her zaman "açık + neden + çözüm" kartı olarak.
- **Format/lint:** `eslint` + `prettier` zorunlu.

### 7.4 Çapraz sözleşme — `packages/shared`
- Bulgu şeması (`finding.schema.json`) **tek kaynaktır**. Üç dil de bundan türetir:
  Python→Pydantic, Go→struct, TS→type. Şema değişmeden üç tarafın tipi değişemez.
- Kontrol kimlikleri (`check-ids.json`) kataloğu ortak; her `check_id` benzersiz ve kalıcı.

### 7.5 Yerelleştirme (i18n) ve dil desteği

GuardHub baştan çok dillidir. Arayüzün yanı sıra — en kritiği — **bulgu metinleri ve çözüm
rehberleri** de her dilde doğru olmalıdır.

**Desteklenen diller (9):**

| Dil | Kod | Not |
|---|---|---|
| İngilizce | `en` | **Varsayılan ve kaynak dil** (source of truth) |
| Almanca | `de` | |
| Türkçe | `tr` | |
| Fransızca | `fr` | |
| İtalyanca | `it` | |
| İspanyolca | `es` | |
| Çince | `zh-CN` | Basitleştirilmiş Çince |
| Hintçe | `hi` | |
| Rusça | `ru` | |

Dokuzu da soldan sağa (LTR) yazılır; bu sürümde RTL gerekmez.

**Dil seçimi mekanizması:**
1. İlk istekte middleware `Accept-Language` başlığını okur ve desteklenen listeyle eşleştirir —
   yani kullanıcı siteye geldiğinde **bilgisayarının dilinde** açılır.
2. Eşleşme varsa o dilde render edilir ve `NEXT_LOCALE` çerezi (HTTP-only) set edilir.
3. Eşleşme yoksa varsayılan **İngilizce (`en`)**.
4. Navbar'da kalıcı bir **dropdown dil seçici** bulunur; kullanıcı dili değiştirir, tercih profilde saklanır.
5. **Güven sayfası** (`trust/[slug]`) de ziyaretçinin diline göre render edilir.

**Çeviri mimarisi (güvenlik açısından kritik kural):**
- **Çalışma anında makine çevirisi YASAK.** Güvenlik talimatı yanlış çevrilirse kullanıcı
  açığı yanlış kapatır. Bu yüzden her metin **önceden, küratörlü** biçimde hazırlanır.
- **Kaynak dil İngilizce'dir.** Tüm anahtarlar önce `en` için yazılır; diğer 8 dil bundan türetilir.
- **Bulgu ve çözüm metinleri kontrol bazlıdır:** Her kontrol kendi `title_key` + `plain_summary`
  + `fix_guidance` metinlerini **9 dilde** taşır. Scanner yalnızca `check_id` + şablon
  parametrelerini döndürür; API katmanı bunu kullanıcının diline çevirir.
- **Çeviri kataloğu konumu:** `packages/shared/i18n/<locale>/`; UI dizeleri ve bulgu/çözüm dizeleri
  ayrı namespace'lerde.
- **Terim sözlüğü (glossary):** Güvenlik terimleri her dilde tutarlı; teknik terimlerin
  (CSP, HSTS, TLS, CVE) çevrilmeyeceği sözlükte işaretlidir.
- **Eksik çeviri davranışı:** Çeviri yoksa İngilizce'ye düşülür (fallback) ve CI uyarı üretir.

**Yeni kontrol eklerken i18n zorunluluğu:** Bir kontrol, metinleri en az `en` için tam ve
anahtarlanmış olmadan "bitti" sayılmaz (bkz. §12). Diğer 8 dil çeviri kuyruğuna girer.

---

## 8. Ürün altyapısı ve yönetim (marka, admin, modüller, AI, öz-izleme, geçmiş)

> Birleştirici ilke (§2.10): **altyapı ve veri modeli şimdi tam kurulur; ağır UI/özellik
> fazlara yayılır** ki hiçbir şey sonradan yeniden yazılmasın.

### 8.1 Marka (branding)
- Her public dokunuş noktasında **GuardHub logosu + "Powered by HKSolutions"** görünür:
  landing, tarama ekranı, dashboard, rapor, güven sayfası, e-posta, fatura, hata sayfaları.
- Marka varlıkları `packages/shared/brand/` ve `apps/web/components/brand/` altında tek kaynaktan.
- Güven sayfası ve raporlar HKSolutions kurumsal kimliğini taşır (ciddiyet ve güven).

### 8.2 Görünür tarama (şeffaflık)
- Tarama bir kara kutu değildir. Kullanıcı **ne taranıyor** adım adım görür: her kontrol
  sırayla "çalışıyor → tamamlandı" olarak canlı güncellenir (`scanner/progress` → API → web).
- Sonuç her zaman kullanıcının site dilinde, sade ve anlaşılır: *açık + neden + çözüm*.

### 8.3 Admin paneli ve modül bayrakları (feature flags)
- Ayrı admin arayüzü (`apps/web/app/admin/` + `apps/api/admin/`), yalnızca `admin` rolü + 2FA.
- **Modül kayıt defteri (`modules/`):** her kontrol/özellik bir **modül**; admin global olarak
  **aç/kapat** yapabilir. Kullanıcı tarafı için değil, yönetim tarafı için.
- Bayraklar iki boyutlu: (1) **global on/off**, (2) **plan bazlı** (`free`/`pro`/`agency` hangi
  modülü görür). Yeni modül önce kapalı yayınlanır, test edilir, sonra kademeli açılır.
- **Admin görünürlüğü:** kullanıcılar, abonelikler, taramalar, modül durumları, sistem sağlığı,
  denetim logları, AI yapılandırması.
- **Altyapı şimdi, UI kademeli:** veri modeli ve API baştan tam; admin UI **MVP'de minimal**
  (modül aç/kapat + kullanıcı/tarama listesi), fazlarla **ayrıntılı ve kapsamlı** hale gelir.

### 8.4 AI sağlayıcı soyutlaması (seam) — `ai/`
- Kodda tek bir `AIProvider` arayüzü vardır; anahtar yokken **no-op** (devre dışı) çalışır ve
  hiçbir çekirdek işlevi bloke etmez.
- Admin'den bir API anahtarı girilince **basitçe** aktif olur; tam kapsamlı AI devreye girer.
- AI bir **opsiyonel zenginleştirme katmanıdır:** bulgu özetleme, rapor dili iyileştirme,
  anormallik tespiti. **Çekirdek tarama ve izleme AI'sız tam çalışır.**
- Şu aşamada yalnızca **seam + yapılandırma** inşa edilir; gerçek AI özellikleri sonra (bkz. §11, Faz 4).

### 8.5 Öz-izleme ve sistem sağlığı — `health/` (AI'sız)
- Her modülün sağlığı sürekli izlenir: çalışıyor mu, hata oranı, gecikme. Bu **düz altyapıdır,
  AI gerektirmez** ve asla bir AI anahtarına bağımlı değildir.
- Kendi sistemimizin güvenliği, GuardHub'ın kendi kurallarıyla düzenli denetlenir (dogfooding, §9.1).
- Sağlık ve denetim verisi admin'de görünür ve **ileride raporlarda kullanılabilir**.
- AI anahtarı girildiğinde bu verinin **üstüne** opsiyonel anormallik tespiti eklenebilir.

### 8.6 Tarama geçmişi ve karşılaştırma
- Kullanıcı tüm önceki taramalarını görür (tarih, puan, bulgu sayısı) — kurumsal, sade bir arayüzde.
- **Karşılaştırma (diff):** son tarama ile bir önceki arasında ne **yeni çıktı**, ne **düzeldi**,
  ne **geri geldi (regresyon)**. Zaman içinde puan trendi gösterilir.
- Bu, elde tutmanın (retention) ana aracıdır; Faz 1'de sürekli izlemeyle birlikte gelir.

### 8.7 Kayıt ve kullanıcı alanı
- **Ücretsiz tek seferlik tarama kayıt gerektirmez** (viral kanca). Kayıt duvarı **değerin
  arkasındadır:** "taramayı kaydet, tekrar tara, karşılaştır" isteyince gelir.
- Kullanıcı alanı (`account/`) kurumsal, güzel ve detaylı: projeler, tarama geçmişi, karşılaştırma,
  güven sayfası yönetimi, abonelik, dil tercihi.
- Dil: kullanıcının bilgisayar dili otomatik + navbar dropdown ile değiştirme (§7.5).

---

## 9. Güvenlik, gizlilik ve tarama etiği

Bu bölüm pazarlık konusu değildir; ihlali bloke edilir.

### 9.1 Kendi güvenliğimiz (dogfooding)
- Tüm sırlar secret manager / env; repoda gerçek sır bulunmaz (CI tarar).
- Veri dinlenirken AES-256, taşınırken TLS 1.3. Dashboard ve admin'de zorunlu 2FA.
- Her hassas işlem `AuditLog`'a yazılır (değişmez).
- GuardHub kendi kurallarını kendi altyapısına uygular; sürüm öncesi kendi taramasından geçer (§8.5).

### 9.2 Tarama etiği (en kritik)
- **Yalnızca izinli hedef.** Bir hedef taranmadan önce sahiplik/erişim doğrulanır
  (DNS TXT kaydı, iyi-bilinen dosya veya meta etiket ile `ownership_verified_at`).
- **Zarar verme.** Yıkıcı, veri değiştiren, hizmet kesen istek yok. Varsayılan pasif + hız-sınırlı.
- **Derin testler (Faz 4 auth/IDOR) yalnızca açık rıza ile**, kullanıcının kendi hesabıyla,
  kapsamı tanımlı ve loglanan biçimde yapılır.
- Hedefin verisi dışarı çıkarılmaz; delil **maskelenir** ve en az biçimde saklanır.

### 9.3 Müşteri verisi
- En az veri ilkesi. Tarama delili gereğinden fazla saklanmaz; saklama süresi tanımlıdır.
- Kullanıcı verisini silme/export (KVKK/GDPR) desteklenir.

---

## 10. Test, CI/CD ve kalite kapıları

- **Her kontrolün testi zorunludur:** sahte/fixtured hedefe karşı pozitif + negatif senaryo.
- **API:** birim + entegrasyon testleri; kritik akışlar (kayıt, tarama, bulgu, karşılaştırma,
  modül aç/kapat) uçtan uca.
- **Go scanner:** eşzamanlılık ve rate-limit testleri; "zarar vermez" davranışı test edilir.
- **AI seam:** anahtar yokken no-op davranışı test edilir (çekirdek bloke olmamalı).
- **CI kapıları (geçmeden merge yok):** lint (ruff/mypy/golangci-lint/eslint) → testler →
  sır taraması → şema uyumu (`packages/shared` türetmeleri güncel mi) → i18n `en` tamlığı.
- **Her yeni kontrol** `docs/checks/` altında belgelenir: ne tespit eder, nasıl doğrular,
  sade dil metni, çözüm metni, yanlış-pozitif riski.
- **Gözlemleme:** structured log + OpenTelemetry trace + Sentry. Taramalar izlenebilir olmalı.

---

## 11. Yol haritası (fazlar, dizine eşlenmiş)

> Süreler tam zamanlı tek kişi varsayımıdır; yarı zamanlıysa iki katı. Her faz sonunda gerçek
> kullanıcı geri bildirimine göre sıralama gözden geçirilir. **Altyapı seam'leri (admin, modül
> bayrakları, AI, sağlık) baştan kurulur; ağır UI fazlara yayılır.**

### Çekirdek / MVP — ~4-6 hafta
**Hedef:** `Gir → Gör → Düzelt` döngüsünü tek kama ile kanıtla.
- `scanner/checks` + `scanner/progress`: 5-6 yüksek sinyalli kontrol + **görünür tarama**.
- `api/scans` + `api/findings`: tarama tetikleme, sade dile çeviri, puan.
- `web/scan`: **ücretsiz tek seferlik tarama** (giriş gerektirmez) — viral kanca.
- `api/auth` + hesap + taramayı kaydet + tekrar tara.
- **Marka:** GuardHub + "Powered by HKSolutions" her ekranda.
- **i18n:** otomatik dil + dropdown; `en` + `tr` tam, diğerleri fallback.
- **Altyapı seam'leri (minimal):** modül kayıt defteri + global aç/kapat, `AIProvider` no-op,
  temel `health/` sağlık kontrolü, minimal admin (modül aç/kapat + liste).
- **Başarı ölçütü:** ilk 20 kullanıcı; en az biri gerçek bir açığını kapatıyor.

### Faz 1 — tekrarlayan gelir + karşılaştırma — ~3-4 hafta (ay 1-2)
- Zamanlanmış otomatik taramalar (scheduler + Redis).
- **Tarama geçmişi + karşılaştırma (diff):** yeni / düzelen / regresyon + puan trendi.
- Yeni açıkta e-posta/Slack uyarısı.
- İlk ücretli plan (`api/billing`) + plan bazlı modül bayrakları.
- **Başarı ölçütü:** ilk ödeyen aboneler; haftalık geri gelen kullanım.

### Faz 2 — satış kancası — ay 2-4
- `api/trust` + `web/trust/[slug]`: çok dilli güven sayfası + müşteri anketi cevabı.
- Repo bağlama (GitHub): bağımlılık/CVE + derin sır taraması.
- Diğer 7 dilin çevirileri tamamlanır.
- **Başarı ölçütü:** güven sayfası bir müşteri anketinde kullanılıyor.

### Faz 3 — büyüme, ekip ve detaylı admin — ay 4-6
- Çoklu proje / ajans katmanı; ekip hesapları + roller.
- **Ayrıntılı ve kapsamlı admin paneli** (kullanıcı/abonelik/sistem/sağlık/denetim ekranları).
- CI/CD entegrasyonu ("yeni kritikte derlemeyi durdur").
- Kontrol seti genişler.

### Faz 4 — derinlik + AI zenginleştirme — ay 6+
- **AI aktivasyonu:** anahtar girilince `AIProvider` devreye girer — bulgu özetleme, anormallik
  tespiti, rapor dili iyileştirme. (Altyapı MVP'den beri hazır; burada yalnızca açılır.)
- Yarı-otomatik yetkilendirme/IDOR testleri (izinli, kapsamlı, loglanan).
- Platform entegrasyonları (GitHub App, Vercel/Netlify, deploy-sonrası tarama).
- Ajanslar için beyaz etiket; "AI ile üretilmiş uygulamalar" paketi.

---

## 12. AI agent çalışma protokolü

Bir AI agent bu repoda çalışırken şu adımları izler:

1. **Önce oku:** bu belge (§2 ilkeler, §5 dizin) + değiştireceğin servisin §7 bölümü +
   (ürün/arayüz işi ise §8) + ilgili `docs/checks/` dosyası.
2. **Sözleşmeyi koru:** Bulgu/kontrol şemasını değiştireceksen önce `packages/shared`'ı güncelle,
   sonra üç dildeki türetmeleri eşle. Şema ile kodu asla ayrı bırakma.
3. **Küçük adım:** Tek bir kontrol, tek bir uç, tek bir sorumluluk ekle/düzelt.
4. **Yeni kontrol eklerken:** `scanner/checks` altında yeni dosya + registry kaydı +
   pozitif/negatif test + `docs/checks/<id>.md` + sade dil/çözüm metni **en az `en` için
   anahtarlanmış** + modül kayıt defterine giriş (varsayılan kapalı). Altısı da olmadan "bitti" deme.
5. **Zarar verme sınırını doğrula:** Eklediğin her ağ davranışı pasif, hız-sınırlı ve
   zaman-aşımlı mı? Değilse ekleme.
6. **AI'a bağımlılık yaratma:** Çekirdek tarama ve izleme AI anahtarı olmadan tam çalışmalı.
   AI yalnızca opsiyonel zenginleştirmedir (§8.4).
7. **Sır gömme:** Hiçbir anahtarı/parolayı koda yazma; `config` ve env kullan.
8. **Kendini test et:** lint + testler yerelde geçmeden PR açma.
9. **Belgeyle çeliştiğinde:** kuralı uygula; uygulanamıyorsa bu belgeye değişiklik öner,
   sessizce aykırı kod yazma.
10. **Açıklanabilirlik:** Ürettiğin her bulgu bir `check_id`'ye ve bir delile izlenebilir olmalı.

**Agent için "bitti" tanımı:** kod + test + doküman + şema uyumu + i18n (`en`) + lint, hepsi yeşil.

---

## 13. Sözlük

- **Check (kontrol):** Tek bir güvenlik durumunu test eden deterministik birim (ör. `exposed_env`).
- **Module (modül):** Admin'den aç/kapat yapılabilen bir kontrol veya özellik (feature flag).
- **Finding (bulgu):** Bir kontrolün ürettiği, sade dile çevrilmiş sonuç + delil + çözüm.
- **Evidence (delil):** Bir bulguyu doğrulayan, maskelenmiş kanıt.
- **ScanDiff (karşılaştırma):** İki tarama arası fark — yeni / düzelen / regresyon.
- **Trust page (güven sayfası):** Bir projenin güvenlik durumunu müşteriye gösteren public sayfa.
- **Probe:** Scanner'ın hedefe attığı güvenli, hız-sınırlı tek istek.
- **AIProvider (seam):** Anahtar girilince aktifleşen opsiyonel AI soyutlaması; yoksa no-op.
- **Ownership verification:** Bir hedefin taranabilmesi için sahipliğin kanıtlanması.

---

## 14. Değişiklik yönetimi

- Bu belge sürümlüdür. Mimari kararlar `docs/adr/` altında ADR olarak kaydedilir.
- Yığına dil/runtime eklemek, tarama etiğini gevşetmek, şema değiştirmek veya çekirdeği bir AI
  anahtarına bağımlı kılmak **ADR gerektirir**.
- Belge güncellemesi, onu etkileyen kod değişikliğiyle **aynı PR'da** yapılır.

> **Son söz:** GuardHub bir güvenlik ürünü. Güveni biz kaybedersek ürün biter. Bu yüzden
> sadelik, zarar vermeme ve dürüst iletişim; hız ve özellik sayısından önce gelir.
