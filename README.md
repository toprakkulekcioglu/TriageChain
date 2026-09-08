<p align="center">
  <img src="assets/brand/triagechain_logo_source.png" alt="TriageChain" width="480">
</p>

# TriageChain

> Windows DFIR triage collector with a tamper-evident, hash-chained chain of custody.
> Runtime dependencies: `pydantic`, `PyYAML`, and `pywin32` (Windows only, VSS).

TriageChain, olay müdahalesi (DFIR) sırasında bir Windows sisteminden hızlı
"triage" delili toplayan ve topladığı her dosya için kırılması tespit edilebilir
bir gözetim zinciri (chain of custody) tutan bir komut satırı aracıdır.

## Kapsam (Faz 1–2 + Faz 4–5)

Şu an çalışan kısım — **toplama ve gözetim zinciri (faz 1)**:

- **Hedef seçimi** — pakete gömülü katalogdan ($MFT, registry kovanları,
  `.evtx` olay günlükleri, prefetch) hedef seçme; `%WinDir%` gibi ortam
  değişkenleri ve `C:\Users\*\NTUSER.DAT` gibi glob'lar çözülür.
- **Toplama** — dosyalar akış halinde okunur, kopyalanırken hash'lenir,
  yazıldıktan sonra yeniden hash'lenip karşılaştırılır.
- **VSS** — kilitli dosyalar için Volume Shadow Copy, `pywin32` ile WMI'nin
  `Win32_ShadowCopy.Create()` metodu doğrudan çağrılarak oluşturulur ve iş
  bitince silinir. `pywin32` yalnızca Windows'ta kurulur ve yalnızca burada
  kullanılır.
- **Chain of custody** — her olay, bir önceki kaydın hash'ine bağlanarak
  yalnızca ekleme yapılan bir JSONL defterine yazılır; defter sonradan
  bağımsız olarak doğrulanabilir.
- **Manifest** — kosunun tamamı `manifest.json` olarak diske yazılır.

Ve **yönlendirme/format dönüştürme (faz 2)**:

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

Ve **Sigma kural tabanlı tespit (faz 4)**:

- **Hayabusa** — toplanan `.evtx` dosyaları Hayabusa'ya verilip Sigma kuralları
  ile taranır; bulgular `detection_manifest.json`'a, aracın ham CSV çıktısı
  vakanın ağacına yazılır. Çağrı sözdizimi ve CSV sütun eşlemesi kod değil
  veridir: `detection/catalog/hayabusa_args.yaml`.
- **En iyi çaba ayrıştırma** — Hayabusa sürümünüzün çıktı başlıkları farklıysa
  koşu düşmez: 0 bulgu + bir uyarı kaydedilir, ham CSV yerinde durur.
- **Güvenlik** — router ile birebir aynı dört kural geçerlidir.
- **Gözetim zinciri** — bulgu başına değil, taranan dosya başına tek bir özet
  olay yazılır; `detection_manifest.json`'ın SHA-256'sı kapanış olayına işlenir.

Ve **otomatik raporlama (faz 5)**:

- **Tek komut, iki çıktı** — `triagechain report`, toplama/yönlendirme/tespit
  manifestlerini ve gözetim zincirinin tam olay listesini `report.json`
  (makine-okur) + `report.html` (insan-okur, tek sayfa) içinde birleştirir.
- **Tamamen offline HTML** — harici CDN/font/script/stil yoktur; olay yerinde
  internetsiz bir makinede açılır. En üstte büyük ve renkli bir "Zincir Durumu:
  GEÇERLİ / GEÇERSİZ" göstergesi bulunur.
- **Raporun kendi bütünlüğü** — yanına `report.json.sha256` yazılır
  (`<hash>  report.json`), böylece raporun sonradan değiştirilip
  değiştirilmediği `sha256sum -c` ile kontrol edilebilir.
- **Kısmi çalıştırmaya dayanıklı** — `route`/`detect` hiç çalıştırılmadıysa
  raporun o bölümü "henüz çalıştırılmadı" der. Rapor katmanı gözetim zincirine
  **yazmaz**, yalnızca okur.

Henüz yok: dış sistem adaptörleri (`integrations/`).

## Kurulum

```bash
python -m venv .venv
.venv\Scripts\activate        # Linux/macOS: source .venv/bin/activate
pip install -e .[dev]
```

## Kullanım

```bash
# Toplama
triagechain collect --config config/triagechain.example.yaml

# Toplananları ayrıştırma araçlarına yönlendirme
triagechain route --config config/triagechain.example.yaml

# Olay günlüklerini Sigma kurallarıyla tarama
triagechain detect --config config/triagechain.example.yaml

# Rapor üretme (JSON + tek sayfa HTML)
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

## Belgeler

- [docs/architecture.md](docs/architecture.md) — mimari ve tasarım kararları
- [docs/chain_of_custody.md](docs/chain_of_custody.md) — hash zinciri şeması
- [docs/config_reference.md](docs/config_reference.md) — konfigürasyon alanları

## Lisans

MIT — bkz. [LICENSE](LICENSE).
