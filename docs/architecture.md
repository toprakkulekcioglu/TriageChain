# Mimari (Faz 1–2 + Faz 4–5)

TriageChain'in ilk fazı tek bir soruya odaklanır: *bir Windows sisteminden
delil niteliğindeki dosyaları, sonradan mahkemede savunulabilecek şekilde nasıl
alırız?* Bu yüzden faz 1'de yalnızca **toplama** ve **gözetim zinciri** vardır.

Faz 2 bunun üstüne **yönlendirme (router)** katmanını ekler: toplanan ham
artefaktları doğru ayrıştırma aracına gönderip çıktılarını vakanın ağacına
yazar.

Faz 4 **tespit (detection)** katmanını ekler: toplanan `.evtx` dosyalarını
Hayabusa ile tarayıp Sigma kural tabanlı bulgular üretir.

Faz 5 ise **raporlama (reporting)** katmanını ekler: önceki üç katmanın
çıktılarını ve gözetim zincirinin tamamını tek bir JSON + tek sayfa HTML
raporunda birleştirir. Bu, çekirdek fazların sonuncusudur.

## Katmanlar

```
cli/         → argparse tabanlı giriş noktası (collect, route, detect, report, verify-custody)
config/      → YAML şeması (pydantic) ve yükleyici
core/        → vaka modeli, hata hiyerarşisi
collection/  → katalog, seçici, VSS, okuyucular, hash, toplayıcı, manifest
custody/     → olay modeli, JSONL depolama, hash zincirli defter
router/      → araç eşleme kataloğu, yönlendirici, yönlendirme manifesti
detection/   → Hayabusa/Chainsaw/YARA çağrı katalogları, tarayıcılar, korelasyon
reporting/   → rapor modeli, rapor üretici (builder), HTML render'ı, yönetici özeti
gui_qt/      → PySide6 masaüstü arayüzü (tema, gömülü fontlar, yedi işlevsel sayfa)
gui/         → eski tkinter arayüzü (duruyor ama `triagechain-gui` artık gui_qt'yi açıyor)
integrations/→ ileride eklenecek adaptörler için boş yer tutucu
```

Bağımlılık yönü tek taraflıdır: `gui_qt/` diğer katmanları **çağırır**,
hiçbir çekirdek katman `gui_qt`'yi (ya da `PySide6`'yı) import etmez —
arayüz tamamen kaldırılsa CLI ve kütüphane aynen çalışmaya devam eder.

Akış her zaman aynıdır:

1. `config/loader.py` YAML'i okur, pydantic ile doğrular ve pydantic'in ham
   hatasını kullanıcıya göstermeden `ConfigError`'a çevirir.
2. `collection/selector.py` konfigürasyondaki hedef kimliklerini katalogdan
   bulur, `%WinDir%` gibi değişkenleri ve glob'ları açarak somut yollara çevirir.
3. `collection/collector.py` her dosyayı okurken aynı anda hash'ler, hedefe
   yazar, sonra **yazılan dosyayı yeniden hash'leyip karşılaştırır**.
4. Her adım `custody/ledger.py` üzerinden deftere işlenir.
5. Kosunun tamamı `manifest.json` olarak diske yazılır.

## Hata felsefesi

İki tür hata vardır ve bunlar bilinçli olarak farklı davranır:

- **Beklenen, artefakt bazlı hatalar** (dosya yok, erişim reddedildi, glob hiçbir
  şeye uymadı): manifeste ve deftere `collection_error` olarak yazılır, koşu
  devam eder. Bir hive okunamadı diye tüm triage'ı çöpe atmak sahada işe yaramaz.
- **Ölümcül hatalar** (`IntegrityError`, `CustodyLedgerError`): hiçbir yerde
  sessizce yutulmaz. Yazılan kopyanın hash'i tutmuyorsa koşu anında durur;
  çünkü bu noktadan sonra üretilen her kayıt şüphelidir.

## VSS kararı: neden `pywin32` (WMI COM)?

Kilitli dosyalar (`$MFT`, registry kovanları) çalışan bir sistemde doğrudan
okunamaz; Volume Shadow Copy üzerinden alınmaları gerekir. Proje boyunca
çalışma zamanı bağımlılıkları bilinçli olarak dar tutuldu (`pydantic`,
`PyYAML`) ve VSS önce `vssadmin`, sonra `powershell.exe` üzerinden WMI ile
metin çıktısı ayrıştırılarak yönetildi. Bu iki adımın da gerçek makinede
sınanmasının ardından (bkz. `docs/hatalar_ve_sonuclar.md`) **kullanıcı
onayıyla** üçüncü bir adıma geçildi: `collection/vss_snapshot.py` artık
`pywin32`'nin `win32com.client` modülüyle WMI'yi **doğrudan** çağırıyor
(`Win32_ShadowCopy.Create` ile oluşturma, WMI örneğinin kendi `Delete_()`
metoduyla silme). Böylece metin ayrıştırma tamamen ortadan kalktı ve ekstra
bir süreç (`powershell.exe`) başlatmaya gerek kalmadı.

`pywin32`, projenin "bağımlılıktan kaçın" ilkesinin **tek, bilinçli
istisnasıdır**: `pyproject.toml`'da `sys_platform == 'win32'` işaretleyicisiyle
listelenir (CI Linux üzerinde çalıştığı için şart), modülün kendisi pywin32
yokken de import edilebilir kalır (import `try/except ImportError` ile
sarılmış) ve yalnızca `VssSnapshot` gerçekten kullanılmaya çalışıldığında
anlamlı bir `CollectionError` verir.

`VssSnapshot` bir context manager'dır; çıkışta — hata olsa bile — golge kopyayı
siler. Temizlik hatası orijinal hatayı maskelemez ama sessizce de geçilmez,
elle silme komutuyla birlikte gürültülü şekilde loglanır. Ham COM istisnaları
dışarı sızmaz, hepsi `CollectionError`'a sarılır.

**Gerçek zaman aşımı (tamamlandı):** `__init__`'teki `timeout` parametresi
artık gerçekten uygulanıyor. Hem oluşturma (`__enter__`) hem silme
(`__exit__`) çağrısı `_run_with_timeout()` ile ayrı bir daemon thread'de
çalıştırılıp `threading.Thread.join(timeout)` ile beklenir; thread kendi
COM apartmanını (`CoInitialize`/`CoUninitialize`) açıp kapatır (WMI
nesneleri apartman-bağlı olduğu için oluşturma/silme AYNI thread'de
kalmalı). Python thread'leri zorla durdurulamadığı için bu gerçek bir
"iptal" değildir — zaman aşımında kontrol çağırana geri döner ama arka
plan thread'i çalışmaya devam edebilir; bu YETİM bir gölge kopya bırakma
riski taşır ve kullanıcıya `vssadmin list shadows` ile elle kontrol
önerisi verilir (gerekçe ve test detayı `aldigim_kararlar.md`'de).

## Çoklu disk/birim desteği

Sistem diskinin dışında `collection.additional_volumes` altında listelenen
her ek birim (`D:`, `E:` vb.) için sadece `$MFT` toplanır — registry
kovanları, olay günlükleri ve prefetch sistem diskine özgü kaldığı için bu
diskler taranmaz. Her ek birim için ad-hoc bir `ResolvedTarget`
(`requires_vss=True`) oluşturulur, `VssSnapshot` o birim için açılır ve
kullanılamayan bir birim (`VssSnapshot` hata verirse) ölümcül sayılmaz —
manifeste/deftere hata olarak yazılır, koşu diğer birimlerle/hedeflerle
devam eder. Var olan `_collect_target()` mantığı (hash/hata işleme)
**birebir yeniden kullanılır**, ek birimler için ayrı bir kod yolu
yazılmamıştır (bkz. `aldigim_kararlar.md`).

## Yönlendirme katmanı (Faz 2)

`router/`, `manifest.json`'daki her `CollectedArtifact`'i tipine göre bir
açık kaynak Eric Zimmerman aracına gönderir:

| `artifact_type_id` | Araç |
|---|---|
| `mft` | MFTECmd |
| `registry_*` (SYSTEM, SAM, SECURITY, SOFTWARE, NTUSER, UsrClass) | RECmd |
| `event_logs` | EvtxECmd |
| `prefetch` | PECmd |

Bu tablo Python'a gömülü değildir; `router/catalog/tool_mapping.yaml` içinde
**veri** olarak durur (toplama kataloğuyla aynı desen). Yeni bir araç eşlemesi
eklemek için kod değiştirmek gerekmez. Her rota bir `tool` adı ve bir `args`
şablon listesi tutar; şablondaki `{input}` toplanan dosyanın yolu,
`{output_dir}` o artefaktın çıktı dizini, `{batch_file}` ise (yalnızca RECmd
rotalarında geçer) RECmd'in `--bn` bayrağına verilecek toplu dosyanın yolu ile
değiştirilir.

RECmd, diğer üç aracın aksine `-f <hive> --csv <dizin>` ile çalışmaz; hangi
anahtar/değerlerin çıkarılacağını `--bn <toplu dosya>` ile ayrıca bilmek
ister. Bu dosya — araçların kendisinin aksine — TriageChain ile **birlikte
dağıtılır**: `router/catalog/recmd_batch/DFIRBatch.reb`, `EricZimmerman/RECmd`
deposundaki MIT lisanslı topluluk standardının belirli bir sürüme sabitlenmiş
kopyasıdır (kaynak/sürüm/SHA-256: yanındaki `PROVENANCE.md`). Kullanıcı
`router.recmd_batch_file` ile kendi dosyasını gösterebilir. Yolun hangisi
olduğu manifest/artefakt verisinden asla türetilmez; ya config'den (mutlak
olduğu şemada doğrulanmış) ya gömülü varsayılandan gelir ve argv'ye her zaman
tek bir liste elemanı olarak girer. Dosyanın varlığı koşu anında kontrol
edilir; yoksa bu ölümcül değildir, aracın kendisi bulunamadığındaki gibi bir
"atlandı" kaydı oluşur.

Toplu dosyanın yolu ve **SHA-256'sı**, RECmd ile işlenen her artefaktın
`artifact_processed` custody olayına yazılır — "bu çıktıyı hangi kural seti
üretti" sorusunun cevabı böylece zincirin parçası olur (bkz.
[chain_of_custody.md](chain_of_custody.md)).

Araçlar TriageChain ile **dağıtılmaz**: kullanıcı kendi kurduğu sürümlerin
yolunu `router.tools` altında bildirir. Bildirilmemiş ya da diskte bulunamayan
bir araç hata değildir; ilgili artefakt "atlandı" olarak hem yönlendirme
manifestine hem deftere yazılır — yani sessizce yok sayılmaz.

Çıktı düzeni:

```
<output_dir>/<case_id>/parsed/<arac>/<artifact_type_id>/            ← aracın CSV çıktısı
<output_dir>/<case_id>/parsed/<arac>/<artifact_type_id>/<dosya>.stdout.log
<output_dir>/<case_id>/parsed/<arac>/<artifact_type_id>/<dosya>.stderr.log
<output_dir>/<case_id>/routing_manifest.json
```

### Güvenlik kuralları (denetlenebilir liste)

Bu katman dış ikilileri çalıştırdığı için kuralları gevşetilemez:

1. **`shell=True` hiçbir yerde kullanılmaz.** Her `subprocess.run` çağrısı
   argüman *listesi* alır (`[exe, "-f", girdi, "--csv", cikti]`), tek bir kabuk
   metni değil. Böylece kabuk metakarakteri enjeksiyonu tamamen ortadan kalkar.
2. **Araç yolları mutlak olmak zorundadır.** Doğrulama `RouterConfig` içinde,
   konfigürasyon yüklenirken yapılır; göreli yol hangi ikilinin gerçekten
   çalıştığını belirsizleştirir (PATH-hijack riski) ve `ConfigError` üretir.
   Dosyanın o anda **var olması aranmaz** — kullanıcı araçları kurmadan önce
   konfigürasyonu yazmış olabilir; varlık kontrolü koşu anında yapılır ve
   ölümcül olmayan bir atlamaya döner.
3. **Her girdi yolu vakanın kendi ağacında olmalıdır.** Araca verilmeden önce
   `dest_path` `resolve()` edilir ve `<output_dir>/<case_id>/artifacts` altında
   olup olmadığı kontrol edilir. Elle düzenlenmiş/bozulmuş bir `manifest.json`
   başka bir yeri gösteriyorsa bu bir işleme hatası olarak kaydedilir ve
   **hiçbir şey çalıştırılmaz**. Kontrol yol metnine değil çözülmüş hedefe
   uygulandığı için `..` ve sembolik bağlantılar da yakalanır.
4. **Her çağrının zaman aşımı vardır** (`router.timeout_seconds`, varsayılan
   300 sn). `TimeoutExpired` yakalanır, `processing_error` olarak kaydedilir;
   tek bir araç tüm koşuyu kilitleyemez.
5. **stdout/stderr diske yazılır** ve yolları hem yönlendirme manifestine hem
   custody kaydına işlenir. "Dış araç gerçekte ne yaptı" sorusunun denetim izi
   budur.
6. **Sıfırdan farklı çıkış kodu ölümcül değildir**: `processing_error` olarak,
   stderr'in ilk 2000 karakterlik özütüyle kaydedilir ve koşu bir sonraki
   artefaktla devam eder.
7. **Yeni üçüncü parti bağımlılık yoktur**: yalnızca stdlib `subprocess` ve
   zaten var olan `pydantic`/`PyYAML`.

Bu katmanda ölümcül sayılan tek iki durum vardır: custody defterine yazamamak
(`CustodyLedgerError`) ve çıktı dizinini hiç oluşturamamak (disk dolu/izin yok/
yolun bir parçası aslında bir dosya — ham `OSError` kullanıcıya sızmadan tipli
`RouterError`'a sarılır). Bir ayrıştırma aracının başarısızlığı asla tüm koşuyu
düşürmez.

## Tespit katmanı (Faz 4)

`detection/`, toplama manifestindeki `artifact_type_id == "event_logs"`
artefaktlarını — yani `.evtx` dosyalarını — Hayabusa'ya verip Sigma kural
tabanlı bulgular üretir. Diğer artefakt tipleri bu katmanın işi değildir;
"atlandı" olarak bile kaydedilmezler.

Yönlendirme katmanının yedi güvenlik kuralı burada **birebir** geçerlidir:
`shell=True` yok, `hayabusa_path` ve `rules_dir` config'de mutlak olmak
zorunda, her girdi yolu `resolve()` + `is_relative_to()` ile vakanın
`artifacts` ağacında olduğu doğrulanmadan hiçbir şey çalıştırılmaz, her
çağrının zaman aşımı var (`detection.timeout_seconds`, varsayılan 600 sn),
stdout/stderr diske yazılır, sıfırdan farklı çıkış kodu ölümcül değildir,
yeni bağımlılık eklenmez.

Çağrı sözdizimi ve CSV sütun eşlemesi koda gömülü değildir;
`detection/catalog/hayabusa_args.yaml` içinde veri olarak durur
(`tool_mapping.yaml` ile aynı desen):

```
argv = [hayabusa_path] + ["csv-timeline", "-f", <girdi>, "-r", <kurallar>, "-o", <cikti.csv>, "--quiet"]
```

**Hayabusa'nın gerçek CLI sözdizimi bu geliştirme ortamında doğrulanamadı**
(araç kurulu değil); yukarıdaki şablon makul bir varsayımdır ve ilk gerçek
çalıştırmada düzeltilmesi gerekebilir — düzeltme YAML'de yapılır, kodda değil.

Aracın çıktısı **en iyi çaba** ile ayrıştırılır: CSV bulunamazsa, okunamazsa
ya da başlıkları tanınmazsa bu ölümcül değildir — bulgu sayısı 0 kalır, ham
dosyanın yolu ve bir uyarı kaydedilir, koşu bir sonraki dosyayla devam eder.
Ham CSV zaten diskte durduğu için hiçbir veri kaybolmaz, sadece yapılandırılmış
hale gelmez.

Çıktı düzeni:

```
<output_dir>/<case_id>/detections/hayabusa/<dosya>.hayabusa.csv
<output_dir>/<case_id>/detections/hayabusa/<dosya>.stdout.log
<output_dir>/<case_id>/detections/hayabusa/<dosya>.stderr.log
<output_dir>/<case_id>/detection_manifest.json
```

Kullanılan Sigma kural klasörünün "parmak izi" `detection_started` custody
olayına yazılır (`rules_dir`, `rules_file_count`, `rules_fingerprint_sha256`).
Router'daki toplu dosya tek bir dosya olduğu için doğrudan hash'lenebiliyor;
kural klasörü ise binlerce dosya içerebildiğinden parmak izi **yapısaldır**:
tüm dosyaların `(göreli yol, boyut)` çiftlerinin sıralı listesinden tek bir
SHA-256 hesaplanır. Dosya eklenmesi/çıkarılması/boyut değişikliği yakalanır,
içeriğin aynı boyutta değiştirilmesi yakalanmaz — bilinçli bir tradeoff,
sınırı [chain_of_custody.md](chain_of_custody.md)'de açıkça yazılıdır.

Custody tarafında bu katmanın kendine özgü tek kuralı var: **bulgu başına
değil, taranan dosya başına tek bir özet olay** yazılır. Detaylı bulgular
yalnızca `detection_manifest.json`'da durur; o dosyanın SHA-256'sı
`detection_completed` olayına işlenerek yine de zincire bağlanır (bkz.
[chain_of_custody.md](chain_of_custody.md)). Bu yüzden manifesti diske yazan
taraf CLI değil, koşunun kendisidir — hash ancak dosya yazıldıktan sonra
hesaplanabilir.

Bu katmanda ölümcül sayılan durumlar router'la aynı gerekçeye sahiptir ve
tipli `DetectionError`'a sarılır: tespit çıktı dizinini ya da tespit
manifestini hiç yazamamak.

## Statik imza taraması (YARA)

`detection/yara_runner.py`, Hayabusa'dan **tamamen bağımsız**, ikinci bir
tespit motorudur — davranışsal (olay günlüğü + Sigma) değil, statik imza
tabanlıdır. Bu yüzden Hayabusa'nın aksine sadece `event_logs` değil,
toplanan **HER** artefakt türü YARA'ya gönderilir. Aynı yedi güvenlik
kuralını (subprocess listesi, `shell=True` yok, mutlak yollar, vakanın
kendi ağacı, zaman aşımı, stdout/stderr diske yazımı, sıfırdan farklı
çıkış kodu ölümcül değil) izler; tek farkı sonucun bir CSV dosyasına değil
doğrudan stdout'a yazılmasıdır, bu yüzden ayrı bir çıktı dosyası yoktur.
Argüman şablonu ve stdout satır deseni `detection/catalog/yara_args.yaml`
içinde veri olarak durur. YARA kural dosyası **dağıtılmaz** (açık kaynak
kural setlerinin çoğu kısıtlayıcı lisanslı — bkz. `aldigim_kararlar.md`);
kullanıcı kendi `.yar` dosyasını `detection.yara_rules_file` ile gösterir.

## İkinci, bağımsız bir Sigma motoru (Chainsaw) ve motor korelasyonu

`detection/chainsaw_runner.py`, Hayabusa'nın mimarisini **birebir** takip
eder (aynı yedi güvenlik kuralı, aynı `Finding`/`DetectionManifest` çıktı
şeması) ama gerçek Chainsaw (WithSecure) ikilisini çağırır ve sonucu ayrı
bir `chainsaw_manifest.json`'a yazar. Kasıtlı mimari karar: Chainsaw'a ait
bir `chainsaw_rules_dir` **yoktur** — Hayabusa'nın kullandığı AYNI
`detection.rules_dir`'i paylaşır. Amaç iki farklı kural setiyle iki farklı
sonuç almak değil, **aynı** kural setiyle iki bağımsız motorun (farklı kod
tabanı, farklı Sigma-yorumlayıcı) aynı sonuca varıp varmadığını görmektir.

`detection/correlation.py` iki farklı korelasyon üretir:

- `correlate_findings(detection, yara)` — Sigma/Hayabusa VE YARA'nın AYNI
  dosyayı (`source_path`) işaretlediği kesişim (statik + davranışsal).
- `correlate_sigma_engines(hayabusa, chainsaw)` — Hayabusa VE Chainsaw'in
  AYNI `(source_path, rule_title)` çiftini bulduğu kesişim (aynı teknik,
  iki bağımsız uygulama).

İkisi de saf küme kesişimidir, hiçbir puanlama/ağırlıklandırma yoktur.
Sonuçlar rapora (`Report.correlated_artifacts` / `Report.engine_
agreements`) ve Yönetici Raporu'nun risk kuralına (`reporting/
executive.py`, her ikisi de "Kritik" sayılır) yansır.

## PE davranış/yetenek analizi (capa)

`detection/capa_runner.py`, Hayabusa/Chainsaw/YARA'dan tamamen farklı bir
soru sorar: bir olay günlüğünü değil, `collection.suspicious_binaries`'daki
(analistin ELLE gösterdiği şüpheli `.exe`/`.dll`) TEK bir yürütülebilir
dosyayı analiz eder. Bunun için toplama katmanına yeni bir kavram eklendi
— `collection.suspicious_binaries: list[str]` — çünkü katalogdaki hiçbir
mevcut hedef (MFT, registry, event log, prefetch) gerçek bir PE dosyası
toplamıyordu; capa'nın girdisi tam olarak budur. Bu liste, katalogdaki
diğer hedefler gibi SABİT bir konum değil, vakaya özgü bir yol listesidir;
hepsi TEK bir `suspicious_binary` artefakt türü altında (VSS gerekmeden)
toplanır (bkz. `collector.py::_collect_suspicious_binaries`).

capa gerçek anlamda "yetenek envanteri" çıkarır ("bu dosya mutex açabilir",
"registry okuyabilir" gibi) — bir Sigma/YARA kuralının aksine "bu davranış
kötü amaçlı" demez. Gerçek, zararsız bir `notepad.exe`'de bile 35 capa
kuralı eşleşti (link function at runtime, check if file exists, query
registry value gibi tamamen sıradan yetenekler). Bu yüzden veri modeli
Finding/DetectionManifest DEĞİL, **YARA'nın `YaraMatch`/`YaraManifest`
şeması yeniden kullanılır** (capa da YARA gibi tek bir dosyaya karşı çalışıp
adlandırılmış kural eşleşmeleri üretir) — ama sonucu **Yönetici Raporu'nun
risk hesabına (`reporting/executive.py`) BİLEREK KATILMAZ** ve YARA/Sigma
ile bir korelasyon üretmez (gerekçe `aldigim_kararlar.md`'de).

capa'nın diğerlerinden mimari farkı: gömülü bir varsayılan kural setiyle
kutudan çıktığı gibi çalışır, `detection.capa_rules_dir` ZORUNLU değildir
(sadece bir override); ayarlanmışsa `-r <klasör>` argümanı KOŞULLU olduğu
için (veri değil) kod tarafından argv'nin başına eklenir.

## Raporlama katmanı (Faz 5)

`reporting/`, önceki katmanların **diske yazdığı** dosyaları okuyup tek bir
rapora dönüştürür. Bu katmanın diğerlerinden üç farkı vardır:

1. **Hiçbir dış program çalıştırmaz** — tamamen kendi Python kodudur, dolayısıyla
   router/detection'ın yedi güvenlik kuralı burada konu dışıdır. Tek risk yüzeyi
   dosya okuma/yazmadır; yazma hatası ham `OSError` olarak sızmaz, tipli
   `ReportingError`'a sarılır.
2. **Custody defterine yazmaz**, yalnızca okur (`read_events` + `verify_chain`).
   Gerekçe: rapor zincirin o andaki fotoğrafıdır; kendisi bir olay yazsaydı
   rapordaki olay listesi ve doğrulama sonucu yazıldığı anda eskimiş olurdu.
3. **Eksik girdiye dayanıklıdır**: yalnızca `manifest.json` zorunludur;
   `routing_manifest.json` ya da `detection_manifest.json` yoksa raporun o
   bölümü "henüz çalıştırılmadı" der, koşu düşmez.

Modüller:

```
reporting/models.py    → Report + katman özetleri (to_dict/to_json_file/from_json_file/_iso
                         deseni collection/router/detection manifestleriyle birebir aynı)
reporting/builder.py   → build_report(config) -> Report, write_report(config, report)
reporting/renderer.py  → render_html(report) -> str (Yönetici + Uzman sekmeleri, saf CSS)
reporting/executive.py → build_executive_summary(report) -> ExecutiveSummary (teknik
                         olmayan, deterministik risk seviyesi -- Yönetici Raporu sekmesi)
reporting/timeline.py  → build_timeline(routing) -> list[TimelineEvent] (birlesik
                         zaman cizelgesi, asagida ayrica anlatiliyor)
```

### Birleşik zaman çizelgesi (Plaso'nun kurulamamasına karşı, dış bağımlılıksız alternatif)

Plaso/log2timeline (roadmap'in "süper zaman çizelgesi" hedefi) bu makinede
gerçekten denenip C++ derleme zinciri eksikliğinden kurulamadı (bkz.
`roadmap.md` → "Daha sonra"). Bunun YERİNE `reporting/timeline.py`,
router'ın **zaten çalıştırdığı** dört EZ Tools'un (MFTECmd/RECmd/EvtxECmd/
PECmd) CSV çıktılarını okuyup tek bir kronolojik listede birleştirir —
hiçbir yeni dış araç/subprocess çağrısı yok, salt-okunur bir CSV
ayrıştırma katmanı (reporting/'in diğer modülleriyle AYNI ilke: dış
program çalıştırmaz, custody'ye yazmaz).

Dört aracın CSV şeması, gerçek 2026.5.0 (net9) ikilileri gerçek örnek
verilere (bir `$MFT`, `NTUSER.DAT`/`SAM` registry kovanları, gerçek bir
`.evtx`, gerçek bir prefetch dosyası) karşı çalıştırılarak doğrulandı
(bkz. `aldigim_kararlar.md`). Önemli mimari noktalar:

- Dosyalar **glob ile** bulunur (`*_Output.csv`), sabit bir adla DEĞİL —
  her arac kendi zaman-damgalı varsayılan dosya adını kullanıyor.
- MFTECmd icin MACB (Modified/Accessed/Changed/Born) deseni uygulanır:
  dört $STANDARD_INFORMATION zaman damgasından her DOLU olan AYRI bir
  olay olur (Plaso'nun kendi super-zaman-cizelgesi yaklaşımıyla aynı).
- PECmd'nin kendiliğinden ürettiği `*_Output_Timeline.csv` (sade
  `RunTime,ExecutableName`) DOĞRUDAN okunur, ana CSV'yi ayrıştırmaya
  gerek yok.
- RECmd'nin CSV'si DEĞER satırı başınadır (bir anahtarın onlarca değeri
  aynı `LastWriteTimestamp`'i taşır) — `(KeyPath, LastWriteTimestamp)`
  çiftine göre TEKİLLEŞTİRİLİR, aksi halde zaman çizelgesi neredeyse
  özdeş satırlarla taşardı.
- Bir aracın çıktısı eksik/bozuksa o kaynaktan hiç olay gelmez (uyarı
  loglanır), diğerleri etkilenmez — "en iyi çaba" ilkesi.

**Kapsam sınırı:** Plaso'nun ~600 ayrıştırıcısının (tarayıcı geçmişi,
disk imajı biçimleri vb.) YERİNE geçmez — sadece TriageChain'in zaten
topladığı/ayrıştırdığı dört kaynağı birleştirir.

Çıktı düzeni:

```
<output_dir>/<case_id>/report.json          ← makine-okur
<output_dir>/<case_id>/report.json.sha256   ← "<hash>  report.json"
<output_dir>/<case_id>/report.html          ← insan-okur, tek sayfa
```

HTML **tamamen offline** açılabilmek zorundadır: harici CDN, font, script ya da
stil referansı yoktur; CSS raporun kendi `<style>` bloğundadır. Dışarıdan gelen
her metin (dosya yolu, kural başlığı, olay yükü) `html.escape`'ten geçer —
manifest içeriği dış araçlardan/kullanıcıdan gelir, rapora ham HTML olarak
sızmamalıdır. Çok bulgulu vakalarda tabloya yalnızca ilk 500 bulgu yazılır
(sayfa açılabilir kalsın diye); bu durum HTML'de açıkça belirtilir, bulguların
tamamı `report.json` içindedir.

Raporun kendisinin sonradan değiştirilip değiştirilmediği zincirle değil,
yanına yazılan `report.json.sha256` ile kontrol edilir; hash `report.json`
diske yazıldıktan **sonra**, dosyanın gerçek içeriği üzerinden
`collection/hashing.py`'deki `hash_file` ile hesaplanır.

## KAPE ile ilişki

`collection/catalog/default_targets.yaml` içindeki yol tanımları, kamuya açık ve
açık kaynak olan **EricZimmerman/KapeFiles** hedef tanımlarıyla kavramsal olarak
uyumludur. Buradan alınan şey yalnızca *bilgi*dir: hangi artefaktın diskte nerede
durduğu. KAPE'nin kodu, hedef dosyalarının kendisi ya da `kape.exe` ikilisi bu
projeye dahil değildir; dolayısıyla TriageChain'i çalıştırmak için KAPE kurulumu
veya lisansı gerekmez. Katalog, ürünün kendi YAML şemasıyla sıfırdan yazılmıştır.

## Test edilebilirlik

Katalog yolu tek bir fonksiyondan (`collection/catalog.default_catalog_path()`)
okunur. Hem şema doğrulaması hem de toplayıcı bu fonksiyonu çağırdığı için
testler tek bir yamayla tüm zinciri sahte bir kataloğa yönlendirebilir. Uçtan
uca test bu sayede `requires_vss: false` olan girdilerle çalışır: gerçek
Windows'a ya da yönetici hakkına ihtiyaç duymaz, CI'da da koşar.

Yönlendirici de aynı deseni kullanır (`router/catalog.default_catalog_path()`)
ve ek olarak `subprocess.run` yamalanabilir olacak şekilde yazılmıştır: testler
`triagechain.router.runner.subprocess.run`'ı `unittest.mock.patch` ile
değiştirir, dolayısıyla test paketi **hiçbir zaman gerçek bir EZ Tools ikilisi
çalıştırmaz** ve araçların kurulu olmasını gerektirmez.

Tespit katmanı da aynıdır (`detection/catalog.default_catalog_path()` +
`triagechain.detection.runner.subprocess.run` yaması): test paketi gerçek bir
Hayabusa kurulumu gerektirmez.

Arayüz testleri de aynı ilkeyi izler: `QT_QPA_PLATFORM=offscreen` ile Qt
gerçek bir ekran/pencere açmadan kendi sanal yüzeyine çizer, testler yalnızca
widget'ların tuttuğu **değerleri** (`.text()`, satır sayısı, buton
etkinliği) doğrular — görüntü karşılaştırması yapılmaz. Vaka verisi
`tmp_path` altına gerçek `CustodyLedger.append_event()` çağrılarıyla
yazıldığı için zincir de gerçekten hesaplanır, sahte bir hash kullanılmaz.

## Masaüstü arayüzü (`gui_qt/`)

```
gui_qt/theme.py       → tek koyu palet, tipografi/boşluk sabitleri, taban QSS,
                        gömülü font yükleme (load_embedded_fonts())
gui_qt/widgets.py     → Card, PrimaryButton, SecondaryButton, Input, MonoInput,
                        MonoLabel, StatusBadge, ProgressBar, Sparkline
gui_qt/main_window.py → sidebar + QStackedWidget, yedi işlevsel sayfa
                        (Dashboard, Toplanan Dosyalar, Delil Zinciri, Bulgular,
                        Raporlar, Vakalar), aksiyon worker'ları
gui_qt/app.py         → giriş noktası (`triagechain-gui`)
gui_qt/assets/fonts/  → gömülü Inter + JetBrains Mono TTF'leri (OFL, PROVENANCE.md)
```

Üç kural bu katmanı ayakta tutuyor:

1. **İş mantığı yok.** Yedi aksiyon (Toplama, Yönlendirme, Tarama, YARA
   Tara, Chainsaw Tara, capa Tara, Rapor Üret) doğrudan `run_collection` /
   `run_router` / `run_detection` / `run_yara_scan` / `run_chainsaw_
   detection` / `run_capa_scan` / `build_report`+`write_report` çağırır;
   dosya yolları `config/loader.py`'nin `resolve_*` fonksiyonlarından gelir.
   Arayüzün kendi yol hesabı ya da kendi sayacı yoktur.
2. **Gösterilen her şey diskten okunur.** Her koşudan sonra `read_snapshot()`
   manifestleri ve defteri yeniden okur; ekrandaki sayı ile dosyadaki veri
   ayrışamaz.
3. **UI thread'i asla bloke edilmez.** Her aksiyon bir `ActionWorker`
   (`QThread`) içinde koşar, sonuç `done`/`failed` sinyalleriyle döner;
   worker hiçbir widget'a dokunmaz. Koşu sırasında butonlar kapanır ve
   belirsiz (indeterminate) ilerleme çubuğu döner.

Hata felsefesi CLI ile aynıdır: tipli hatalar (`ConfigError`,
`IntegrityError`, `CustodyLedgerError`, `RouterError`, `DetectionError`,
`ReportingError`) zaten anlaşılır mesaj taşıdığı için doğrudan durum
satırına yazılır; beklenmeyen bir istisna da yakalanıp "Bir şeyler ters
gitti: …" cümlesine çevrilir. **Ham Python traceback'i hiçbir koşulda
kullanıcıya gösterilmez.**

## Dağıtım: standalone `.exe`

`triagechain_gui.spec` (PyInstaller, `--onefile`) arayüzü tek bir
`TriageChainKonsolu.exe`'ye paketler — hedef makinede Python kurulu
olması gerekmez. Gömülü fontlar (`gui_qt/assets/fonts/`) `pyproject.toml`
paket verisi olarak listelendiği için PyInstaller'ın veri toplama adımına
ekstra bir şey yapılmadan dahil olur. BYO-araç mimarisi burada da geçerli:
Hayabusa/Chainsaw/YARA/EZ Tools ikilileri `.exe`'ye **gömülmez**, kullanıcı
kendi kurduğu araçların yolunu konfigürasyonda gösterir.

## Bilinen sınırlar (güncel)

- Ek disklerde (`collection.additional_volumes`) sadece `$MFT` alınır;
  registry/olay günlüğü/prefetch sistem diskine özgü kalır (bilinçli
  kapsam sınırı, bkz. "Çoklu disk/birim desteği" yukarıda).
- Zaman damgası otoritesi (TSA) entegrasyonu yoktur; olay yükünde `tsa_token`
  alanı bu iş için ayrılmış ve şimdilik hep `null` (bilerek eklenmedi — yeni
  bir üçüncü parti bağımlılık gerektirir, çevrimdışı-öncelikli tasarımla
  gerilir; bkz. `roadmap.md`).
- Plaso/log2timeline (süper zaman çizelgesi) henüz eklenmedi — roadmap'te
  sıradaki madde.
- Volatility 3 (bellek analizi) ve Timesketch/ELK (web tabanlı çok
  kullanıcılı görselleştirme) kapsam dışı bırakıldı — ikisi de projenin
  "tek kullanıcı, tek makine, tamamen offline" tasarım ilkesiyle gerilir.
- Defter tablosunda per-event doğrulama yapılmaz (zincirin tamamına
  `verify_chain` bakar) ve arayüzde yalnızca son 50 olay listelenir.

**Artık geçerli olmayan eski sınırlar** (tamamlandı, bkz. `aldigim_
kararlar.md`): "custody defterine aynı anda tek yazıcı" (stdlib dosya
kilidiyle çözüldü), "sadece sistem diskinin $MFT'si" (çoklu disk desteği
eklendi), "arayüzde yalnızca Dashboard işlevsel" (yedi sayfanın hepsi
işlevsel), "VSS'te gerçek zaman aşımı yok" (ayrı thread + `join(timeout)`
ile çözüldü).
