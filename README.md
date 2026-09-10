<p align="center">
  <img src="assets/brand/triagechain_logo_source.png" alt="TriageChain" width="480">
</p>

# TriageChain

> Windows DFIR triage collector with a tamper-evident, hash-chained chain of
> custody — collection, format conversion, four independent detection engines,
> a unified timeline, offline HTML reporting, and a PySide6 desktop GUI.
> Runtime dependencies: `pydantic`, `PyYAML`, `PySide6`, and `pywin32`
> (Windows only, VSS).

TriageChain, olay müdahalesi (DFIR) sırasında bir Windows sisteminden hızlı
"triage" delili toplayan ve topladığı her dosya için kırılması tespit edilebilir
bir gözetim zinciri (chain of custody) tutan bir araçtır — hem komut satırından
hem tam işlevli bir masaüstü uygulamasından (`triagechain-gui`) kullanılabilir.

## Kapsam

**Toplama ve gözetim zinciri:**

- **Hedef seçimi** — pakete gömülü katalogdan ($MFT, registry kovanları,
  `.evtx` olay günlükleri, prefetch) hedef seçme; `%WinDir%` gibi ortam
  değişkenleri ve `C:\Users\*\NTUSER.DAT` gibi glob'lar çözülür.
- **Toplama** — dosyalar akış halinde okunur, kopyalanırken hash'lenir,
  yazıldıktan sonra yeniden hash'lenip karşılaştırılır. Windows'un 260
  karakter `MAX_PATH` sınırı `\\?\` uzun-yol önekiyle aşılır.
- **VSS** — kilitli dosyalar için Volume Shadow Copy, `pywin32` ile WMI'nin
  `Win32_ShadowCopy.Create()` metodu doğrudan çağrılarak oluşturulur ve iş
  bitince silinir.
- **İçe aktarma modu** — canlı bir sisteme ihtiyaç yok: KAPE gibi başka bir
  araçla ZATEN toplanmış bir klasör/ZIP/RAR/7z de (`collection.source_root`)
  analiz edilebilir; bu modda VSS hiç açılmaz.
- **Çoklu disk desteği** — `collection.additional_volumes` ile ek disklerin
  `$MFT`'si de toplanır.
- **Chain of custody** — her olay, bir önceki kaydın hash'ine bağlanarak
  yalnızca ekleme yapılan bir JSONL defterine yazılır (çoklu-yazıcı güvenli,
  dosya kilitleme ile); defter sonradan bağımsız olarak doğrulanabilir.

**Yönlendirme/format dönüştürme:**

- **Router** — `manifest.json`'daki her artefakt tipine göre doğru açık kaynak
  Eric Zimmerman aracına gönderilir (`mft` → MFTECmd, `registry_*` → RECmd,
  `event_logs` → EvtxECmd, `prefetch` → PECmd). Eşleme kod değil veridir:
  `router/catalog/tool_mapping.yaml`.
- **Araçlar dağıtılmaz** — kendi kurduğunuz sürümlerin **mutlak** yolunu
  `router.tools` altında bildirirsiniz. Bildirilmemiş/bulunamayan araç hata
  değil, kaydedilen bir "atlandı"dır.
- **Güvenlik** — `shell=True` hiç kullanılmaz (argüman listesi), araç yolları
  mutlak olmak zorundadır, her girdi yolu vakanın kendi çıktı ağacında
  olduğu doğrulanır ve her çağrının zaman aşımı vardır. Ayrıntılar:
  [docs/architecture.md](docs/architecture.md).
- **Denetim izi** — her aracın stdout/stderr çıktısı diske yazılır, yolları ve
  çıkış kodu hem `routing_manifest.json`'a hem gözetim zincirine işlenir.

**Beş bağımsız tespit motoru:**

- **Hayabusa** ve **Chainsaw** — toplanan `.evtx` dosyaları Sigma kurallarıyla
  taranır; İKİ BAĞIMSIZ motor AYNI kural setiyle çalıştırılıp sonuçların
  örtüşüp örtüşmediği (`detection/correlation.py`) görülür.
- **YARA** — statik imza taraması.
- **capa** — PE dosyaları üzerinde otomatik davranış/yetenek analizi
  (`collection.suspicious_binaries` ile analistin gösterdiği dosyalarda);
  bilerek risk skoruna katılmaz, çünkü "yetenek" tespit eder, kötü amaçlı
  davranış değil.
- **Hash listesi (watchlist/IOC)** — toplanan HER dosyanın zaten hesaplanmış
  hash'i, analistin verdiği bilinen-kötü bir listeyle karşılaştırılır; hiçbir
  dış araç çalıştırmaz (saf Python karşılaştırması) ve bir eşleşme, tam
  eşleşme olduğu için EN GÜÇLÜ risk sinyali sayılır.
- **En iyi çaba ayrıştırma** — bir aracın çıktı başlıkları farklıysa koşu
  düşmez: 0 bulgu + bir uyarı kaydedilir, ham çıktı yerinde durur.
- **Gözetim zinciri** — bulgu başına değil, taranan dosya başına tek bir özet
  olay yazılır; her manifestin SHA-256'sı kapanış olayına işlenir.

**Birleşik zaman çizelgesi:**

- MFTECmd/RECmd/EvtxECmd/PECmd çıktılarından (yeni bir dış araç eklemeden)
  kronolojik tek bir liste — Plaso'nun ~600 ayrıştırıcısının yerini TUTMAZ,
  sadece TriageChain'in zaten topladığı dört kaynağı birleştirir.

**Otomatik raporlama:**

- **Tek komut, iki çıktı** — `triagechain report`, tüm manifestleri ve
  gözetim zincirinin tam olay listesini `report.json` (makine-okur) +
  `report.html` (insan-okur, tek sayfa, Yönetici/Uzman iki sekmeli) içinde
  birleştirir.
- **Tamamen offline HTML** — harici CDN/font/script/stil yoktur; olay yerinde
  internetsiz bir makinede açılır. En üstte büyük ve renkli bir "Zincir Durumu:
  GEÇERLİ / GEÇERSİZ" göstergesi bulunur.
- **Raporun kendi bütünlüğü** — yanına `report.json.sha256` yazılır.
- **Kısmi çalıştırmaya dayanıklı** — `route`/`detect` hiç çalıştırılmadıysa
  raporun o bölümü "henüz çalıştırılmadı" der.

**Masaüstü arayüzü (`triagechain-gui`):**

- PySide6 ile yazılmış, sekiz sayfalı (Dashboard, Toplanan Dosyalar, Delil
  Zinciri, Bulgular, Raporlar, Vakalar, Zaman Çizelgesi, Ayarlar) tek pencereli
  bir uygulama; gömülü Inter/JetBrains Mono fontları, standalone `.exe` olarak
  paketlenir (`triagechain_gui.spec`).
- **"Yeni Vaka Oluştur" sihirbazı** — KAPE'nin kendi arayüzündeki
  kaynak/hedef seçim deneyimini taklit eder: kullanıcı dosya/klasör seçer,
  YAML konfigürasyonu arka planda üretilir (hiç elle yazılmaz). ZIP/RAR/7z
  arşivleri otomatik çıkartılır (arka planda, arayüz donmadan); bir arşivde
  birden fazla makine varsa hepsi tek seferde ayrı vaka olarak oluşturulabilir.
- **Açık/koyu tema + çok dil desteği** — Ayarlar sayfasında anında geçiş.
  Şu an TR + EN tam çevrili; ES/DE/PT/FR seçilebilir ama henüz çevrilmedi.

Henüz yok: dış sistem adaptörleri (`integrations/`), Plaso entegrasyonu
(bilerek ertelendi — bkz. `docs/roadmap.md`).

## Kurulum

```bash
python -m venv .venv
.venv\Scripts\activate        # Linux/macOS: source .venv/bin/activate
pip install -e .[dev]
```

## Kullanım

### Masaüstü arayüzü

```bash
triagechain-gui
```

"Yeni Vaka Oluştur" sihirbazı elle YAML yazmadan (kaynak dosya/klasör seçerek)
bir vaka oluşturur; alternatif olarak elle hazırlanmış bir `.yaml` da
yüklenebilir. Toplama/yönlendirme/tespit/rapor adımlarının hepsi arayüzden
tek tıkla çalıştırılabilir.

### Komut satırı

```bash
# Toplama
triagechain collect --config config/triagechain.example.yaml

# Toplananları ayrıştırma araçlarına yönlendirme
triagechain route --config config/triagechain.example.yaml

# Olay günlüklerini Sigma kurallarıyla tarama (iki bağımsız motor)
triagechain detect --config config/triagechain.example.yaml
triagechain chainsaw-scan --config config/triagechain.example.yaml

# Statik imza taraması ve PE yetenek analizi
triagechain yara-scan --config config/triagechain.example.yaml
triagechain capa-scan --config config/triagechain.example.yaml

# Bilinen-kötü hash listesiyle (watchlist/IOC) karşılaştırma
triagechain watchlist-check --config config/triagechain.example.yaml

# Rapor üretme (JSON + tek sayfa HTML, zaman çizelgesi dahil)
triagechain report --config config/triagechain.example.yaml

# Gözetim zincirini doğrulama
triagechain verify-custody --log C:\TriageChain\output\CASE-2026-001\custody.jsonl --case-id CASE-2026-001
```

`collect` komutu, artefakt bazında hatalar olsa bile 0 ile çıkar; sadece
konfigürasyon, bütünlük veya defter hatalarında sıfırdan farklı bir kod döner.
`route` ve `detect` de aynı şekilde davranır (atlanan/başarısız artefakt koşuyu
düşürmez); `manifest.json` yoksa 2 ile çıkıp önce `collect` çalıştırmanızı
söylerler. `report` de aynı desendedir (`manifest.json` yoksa 2) ve raporu
yazsa bile zincir o an geçersizse 1 döner. `verify-custody` zincir geçerliyse
0, geçersizse 1, dosya yoksa 2 döner.

`route` ve `detect`, olaylarını toplamanın yazdığı **aynı** `custody.jsonl`
dosyasına ekler; bir vaka için tek bir zincir vardır.

Kilitli dosyaları (registry kovanları, `$MFT`) toplamak için aracın **yönetici
haklarıyla** ve gerçek Windows üzerinde çalıştırılması gerekir; aksi halde bu
hedefler hata olarak kaydedilir ve diğerleriyle devam edilir.

## Testler

```bash
pytest
```

Test paketi gerçek VSS veya yönetici hakkı gerektirmez: uçtan uca test,
`requires_vss: false` olan sahte bir katalogla `tests/fixtures/fake_artifacts/`
altındaki dosyaları toplar. Yönlendirme ve tespit testleri de gerçek bir EZ
Tools ikilisi ya da Hayabusa kurulumu gerektirmez: `subprocess.run`
`unittest.mock` ile yamalanır.

Tüm testler (eskiden `tests/unit/`/`tests/integration/`e dağılmış onlarca
dosya) **tek bir dosyada** duruyor: [`tests/test_all.py`](tests/test_all.py).
Yeni bir test eklenecekse bu dosyanın **sonuna** eklenir; `pytest` tek
seferde tümünü çalıştırır, ayrı dosya oluşturup ayrı ayrı çalıştırmaya
gerek kalmaz.

Gerçek araçlara/gerçek veriye karşı (mock'suz) doğrulama için ayrı bir
script var: `scripts/system_check.py`. `pytest`'in aksine CI'da ÇALIŞMAZ
(gerçek Windows araçları ve bir geliştiricinin kendi makinesindeki gerçek
vaka verisi gerektirir) — sadece elle, bu türden bir ortamda çalıştırılır:

```bash
python scripts/system_check.py            # tüm kontroller
python scripts/system_check.py --list     # kontrolleri listele
```

## Belgeler

- [docs/ozellikler.md](docs/ozellikler.md) — tüm özelliklerin ayrıntılı listesi
- [docs/architecture.md](docs/architecture.md) — mimari ve tasarım kararları
- [docs/chain_of_custody.md](docs/chain_of_custody.md) — hash zinciri şeması
- [docs/config_reference.md](docs/config_reference.md) — konfigürasyon alanları
- [docs/roadmap.md](docs/roadmap.md) — yapılanlar / sıradaki işler

## Lisans

MIT — bkz. [LICENSE](LICENSE).
