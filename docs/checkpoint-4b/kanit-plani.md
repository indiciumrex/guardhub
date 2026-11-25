# Kapsam koruyucu (scope guard) + durdurma anahtarı (kill switch) canlı kanıt planı

> **Durum: ÇALIŞTIRILDI ve GEÇTİ (2026-11-25 11:27Z, kurucu onayıyla, yalnızca guardhub.dev).**
> 34 kapsam denemesi ağa çıkmadan reddedildi; 8 istek gönderildi, nginx 8 gördü (hepsi GET,
> en az 999 ms arayla, hariç yol yok); durdurma görüldükten sonra son istek 949 ms; genel
> durdurma önceden kuruluyken 0 istek. Kanıt sunucuda: `/opt/guardhub/proof/20261125T112726Z/`.
> İlk deneme (11:26Z) rapor dosyası yazılamadığı için (izin hatası, betik düzeltildi) sayılmadı.

## 1. Neyi kanıtlıyoruz (ADR-0008 §8.1)

1. **Kapsam koruyucu:** başka alan adı, alt alan adı, başka şema, başka port ve hariç tutulan
   yollar — kodlanmış (`%2e%2e`), `;param`, ters eğik çizgi ve büyük harf biçimleri dahil — **ağa
   hiç çıkmadan** reddedilir; hedefin kendi erişim kaydında hiç görünmez.
2. **Durdurma anahtarı:** test sürerken yönetici panelinden "bu taramayı durdur" basıldığında,
   anahtarın görüldüğü andan son isteğe kadar geçen süre **≤ 2 s**; durdurma önceden
   kuruluysa **sıfır istek**.
3. **Hız:** iki istek arası en az ~1 s (1 istek/sn), yalnızca GET.

Kanıt iki taraflıdır: tarayıcının raporu **ve** hedefin kendi (nginx) kaydı birbirini tutmalı:
nginx'in gördüğü GuardHub-Active istek sayısı = raporun "gönderildi" sayısı.

## 2. Hazırlık (yapıldı, CI'da)

- `scanner activeproof` komutu: tek modül, tek origin, üretim yolu (`active.Client` +
  `activescan.Run`), JSON rapor. Lab dışında yalnızca `SCANNER_ACTIVE_ENABLED=true`,
  `--confirm` = origin ve **o anda yeniden** sahiplik kanıtı ile çalışır; aksi hâlde hiç istek
  göndermez.
- **Lab provası CI'da:** Gate M işinde (`active-lab`) her main çalışmasında `av-xss.lab.test`'e
  karşı aynı kanıt koşar: kapsam denemeleri reddedilmeli, 8 istekten sonra durdurma ≤ 2 s,
  hız ≥ 0,9 s/istek, ve hedefin kendi erişim kaydı (avlab) ile sayılar eşleşmeli
  (`test_corpus/active/check_activeproof.py`). Kırmızıysa kapı kırmızı.
- **Bu hazırlıkta bulunan gerçek hata düzeltildi:** hariç tutulan yollar nokta-segmenti
  çözümlenmeden karşılaştırılıyordu; `/x/%2e%2e/admin`, `/admin;x=1`, `\admin` gibi biçimler
  koruyucudan geçebiliyor, nginx/Tomcat ise bunları `/admin` olarak sunuyordu. Origin
  koruması (başka host/port/şema) etkilenmemişti. Düzeltme + testler bu PR'da.

## 3. Hedef ve parametreler

| | Seçim | Gerekçe |
|---|---|---|
| Hedef | **https://guardhub.dev** (önerim) | Sunucu bizim: nginx kaydını kanıt olarak alabiliyoruz; sahiplik dosyası zaten yayında (Gate F öz-taraması her dağıtımda bunu kullanıyor). sunizeka.net de doğrulanmış ama sunucu tarafı kaydına erişimimiz yok. |
| Modül | **active_xss** (tek modül) | Etkisiz işaretçiler (`<ghx7 data-gh=1>`), hiçbir şey çalışmaz; parametre başına birkaç istek, durdurmayı test ortasında görecek kadar uzun. |
| Başlangıç yolları | `/account/login?next=/account`, `/account/register?next=/account` | guardhub.dev'in GET parametresi taşıyan herkese açık sayfaları. |
| Hariç | `/admin`, `/api`, `/account/projects`, `/account/settings` | Yönetici ve API yüzeyi hiç denenmez; kapsam denemeleri bunların her biçimini dener. |
| Hız / bütçe | 1 istek/sn, en fazla 100 (modül) | Üretim varsayılanı; değiştirilemez. |
| Süre | ~1–2 dk | Keşif ≤ 25 sayfa. |

## 4. "git" sonrası tek adım (sunucuda)

```sh
cd /opt/guardhub/current && GUARDHUB_FOUNDER_GO=yes bash ops/active-proof/run-proof.sh admin
```

Betik sırasıyla:

1. CD kilidini alır (kanıt sırasında dağıtım başlamaz).
2. **Yalnızca kanıt süresince** nginx'te User-Agent'ı `GuardHub-Active/` olan istekleri
   `/var/log/nginx/guardhub-active-proof.log`'a yazdırır (host, URI, UA; IP yok). Çıkışta ne olursa
   olsun eski yapılandırma geri yüklenir (`nginx -t` + reload).
3. **Çalışma 1:** canlı tarayıcı imajından tek seferlik bir konteyner (salt okunur, tüm yetkiler
   düşürülmüş) `activeproof` çalıştırır. Üretim tarayıcı servisi **kapalı kalır**.
   Betik "şimdi durdur" dediğinde (~10 s sonra) kurucu yönetici panelinde **Tarama Yönetimi →
   Durdurma anahtarı → tarama kimliği → Durdur**'a basar (denetim kaydına yazılır).
   (Alternatif: `... run-proof.sh auto` — betik 8 istekten sonra anahtarı kendisi kurar.)
4. Rapor + nginx kaydı `check_activeproof.py` ile karşılaştırılır.
5. **Çalışma 2:** genel durdurma anahtarı önceden kurulur → `activeproof` hiç istek göndermeden
   çıkmalı (çıkış kodu 5) ve nginx kaydında yeni satır olmamalı. Anahtar sonra kaldırılır.
6. Kanıtlar: `/opt/guardhub/proof/<UTC-zaman>/` (report-run1.json, access-run1.log,
   report-run2.txt, access-run2.log, summary.txt). Sır içermez.

## 5. Beklenen kanıt (başarı ölçütleri)

- `scope_probes`: ~34 deneme, hepsi `scope_refused`; nginx kaydında `gh-scope-probe` veya hariç
  yol **yok**.
- `kill.stop_latency_ms ≤ 2000`, `check_error` = durdurma, sonrası istekler `killed` olarak
  reddedilmiş.
- `min_gap_ms ≥ 900`; tüm istekler GET.
- nginx'teki GuardHub-Active satır sayısı = `sent`.
- Çalışma 2: çıkış 5, nginx'te 0 satır.
- Yönetici denetim kaydında `active.kill` satırı (zaman, aktör).

## 6. Durdurma ve geri alma

- Herhangi bir anda: yönetici paneli genel durdurma **veya** sunucuda
  `docker exec guardhub-redis-1 sh -c 'REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli SET gh:active:kill 1'`
  — tarayıcı en geç ~1 s içinde durur; Redis'e ulaşamazsa da durur (fail-closed).
- `Ctrl-C` konteyneri durdurur; betik nginx'i yine geri yükler.
- 3 ardışık 5xx veya gecikme artışında test kendini durdurur (`target_stressed`).
- Kalıcı hiçbir değişiklik yok: nginx eski hâline döner, üretim tarayıcıda aktif test kapalı,
  modül bayrakları kapalı, `active_testing_approved=false`.

## 7. Bu kanıttan sonra bile açılmayanlar

Müşteri hedeflerinde aktif test için ayrıca gerekenler (her biri ayrı kurucu kararı):
rıza metninin hukuk onayı (taslak kurucuya özel olarak iletildi; bu açık repoda değil), rıza arayüzü ve API'si, aynı origin'de
tek aktif test kilidi, SSRF için OOB sunucu
(şartname ve maliyet kurucuya özel olarak iletildi). İstek günlüğü 30 gün saklanır ve günlük iş siler (kurucu kararı 2026-11-25, migration 0018).
