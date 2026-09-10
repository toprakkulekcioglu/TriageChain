# Konfigürasyon Referansı

TriageChain tek bir YAML dosyasıyla çalıştırılır. Örnek:
`config/triagechain.example.yaml`. Dosya `case`, `collection`, `custody`,
`router`, `detection` ve `logging` bölümlerinden oluşur.

## `case`

| Anahtar | Tip | Zorunlu | Varsayılan | Anlamı |
|---|---|---|---|---|
| `case_id` | string | Evet | — | Vaka kimliği. Dosya sistemi yolu olarak kullanıldığı için yalnızca harf, rakam, `-` ve `_` içerebilir; aksi halde `ConfigError`. |
| `operator` | string | Evet | — | Toplamayı yapan kişi. Her gözetim zinciri kaydına yazılır. |
| `description` | string | Hayır | `""` | Serbest açıklama. |

## `collection`

| Anahtar | Tip | Zorunlu | Varsayılan | Anlamı |
|---|---|---|---|---|
| `targets` | string listesi | Evet | — | Toplanacak artefakt kimlikleri. Liste boş olamaz ve her kimlik gömülü katalogda (`collection/catalog/default_targets.yaml`) bulunmalıdır; bulunmayanlar tek tek isimleriyle raporlanır. |
| `hash_algorithm` | `sha256` \| `sha1` \| `md5` | Hayır | `sha256` | Artefakt hash'lerinde kullanılan algoritma. Adli kullanım için `sha256` önerilir; `sha1`/`md5` yalnızca eski sistemlerle uyum içindir. |
| `output_dir` | string (yol) | Evet | — | Çıktı kökü. Bu dizin yoksa oluşturulur, ancak **üst dizini önceden var ve yazılabilir olmalıdır**; değilse `ConfigError`. Diğer tüm yol alanlarının (`router.tools`, `detection.*_path` vb.) aksine **mutlak olması zorunlu değil** — bilinçli bir tasarım kararı: bu alanı besleyen tek kaynak analistin kendi yazdığı, güvenilir konfigürasyon dosyasıdır, güven sınırını aşan bir girdi değildir (bkz. `aldigim_kararlar.md` → güvenlik incelemesi). |
| `additional_volumes` | string listesi | Hayır | `[]` | Sistem diski DIŞINDAKİ birimler (örn. `["D:", "E:"]`) — her biri için AYRI bir gölge kopya açılıp yalnızca o birimin `$MFT`'si toplanır (bkz. aşağıdaki not). Her değer bir sürücü harfi olmalı (`"D:"` ya da `"D:\\"`); başka bir şey `ConfigError` üretir. Normalize edilip büyük harfe, sondaki `\` olmadan saklanır. |
| `suspicious_binaries` | string listesi | Hayır | `[]` | Analistin ELLE gösterdiği şüpheli yürütülebilir (`.exe`/`.dll`) dosyaların **mutlak** yolları — capa'nın (bkz. `detection.capa_path`) girdisi. Katalogdaki diğer hedefler gibi sabit bir konum DEĞİL: analist neyi şüpheli bulduysa onu yazar. Hepsi TEK bir `suspicious_binary` artefakt türü altında toplanır, VSS gerekmez. |
| `source_root` | string (yol) veya `null` | Hayır | `null` | **İçe aktarma modu** (bkz. aşağıdaki bölüm) — BAŞKA bir araçla (örn. KAPE) ÖNCEDEN toplanmış bir artefakt ağacının kökü. Ayarlanmışsa katalogdaki TÜM hedefler (`%SystemDrive%`'a göre çözülenler dahil) bu kök altına yeniden köklendirilir ve VSS HİÇBİR ŞEKİLDE açılmaz. `null` ise (varsayılan) davranış hiç değişmez: canlı `%SystemDrive%`'a karşı toplar. |

Çıktı düzeni:

```
<output_dir>/<case_id>/artifacts/<hedef_kimligi>/<dosya_adi>
<output_dir>/<case_id>/manifest.json
<output_dir>/<case_id>/custody.jsonl        (custody.log_path boşsa)
```

Aynı adlı dosyalar (örneğin her kullanıcının `NTUSER.DAT`'ı) birbirinin üstüne
yazılmaz; ikinci ve sonrakiler `NTUSER.DAT.1`, `NTUSER.DAT.2` şeklinde saklanır.

### Katalogdaki hedef kimlikleri

| Kimlik | VSS gerekir mi | Ne alır |
|---|---|---|
| `mft` | Evet | Sistem diskinin `$MFT` dosyası |
| `registry_system` | Evet | `SYSTEM` kovanı |
| `registry_sam` | Evet | `SAM` kovanı |
| `registry_security` | Evet | `SECURITY` kovanı |
| `registry_software` | Evet | `SOFTWARE` kovanı |
| `registry_ntuser` | Evet | Her kullanıcının `NTUSER.DAT` kovanı |
| `registry_usrclass` | Evet | Her kullanıcının `UsrClass.dat` kovanı |
| `event_logs` | Hayır | `winevt\Logs\*.evtx` |
| `prefetch` | Hayır | `Prefetch\*.pf` |

### Neden sadece `$MFT` çoklu diske açık?

`additional_volumes`'daki her birim için sadece `$MFT` toplanır —
`mft_d`, `mft_e` gibi bir `artifact_type_id` ile (harf küçük, `mft_<harf>`
biçiminde). Registry kovanları, event log ve prefetch BİLEREK dahil
edilmedi: bunların hepsi Windows KURULUMUNA özgü, sistem diski dışında bir
birimde anlamlı bir karşılıkları yok (bir D: verisi diskinin kendi
`SYSTEM` kovanı olmaz). `$MFT` ise her NTFS biriminde ayrı ayrı var olan,
biricik şekilde disk-geneli bir yapı — bu yüzden tek çoklu-disk hedefi o.

### `suspicious_binaries` neden ayrı bir liste?

Katalogdaki her hedef (MFT, registry, event log, prefetch) Windows
kurulumunda SABİT, herkesçe bilinen bir konumda durur. `suspicious_
binaries` farklı: analistin BİR VAKAYA ÖZGÜ olarak "bu dosya şüpheli"
diye elle işaret ettiği yürütülebilirler. Bu yüzden bir katalog girdisi
değil, doğrudan bir yol listesi — capa (bkz. `detection.capa_path`) bu
listedeki dosyaları tarar, katalogdaki hiçbir hedefi taramaz.

### İçe aktarma modu (`source_root`) — canlı sistem yerine önceden toplanmış bir artefakt ağacı

TriageChain'in çekirdek varsayımı "canlı, çalışan bir Windows sistemine
karşı topla" idi. `collection.source_root` bunu genişletir: BAŞKA bir
araçla (tipik örnek: KAPE, `--zip` çıktısı) önceden toplanmış, artık
kilitli OLMAYAN düz kopyalardan oluşan bir klasör ağacını "vaka" olarak
kabul eder — gerçek bir Windows sistemi ya da yönetici hakları hiç
gerekmez.

Gerçek bir KAPE çıktısı (`C\$MFT`, `C\Windows\System32\config\SYSTEM`,
`C\Windows\System32\winevt\Logs\*.evtx`, `C\Users\<kullanıcı>\NTUSER.DAT`
gibi, orijinal `C:\` yapısını `C\` alt klasörü altında birebir taşıyan bir
zip) açıldığında, `source_root`'u o `C\` klasörünün **kendisine**
gösterin:

```yaml
collection:
  targets: ["mft", "registry_system", "registry_sam", "registry_security",
            "registry_software", "registry_ntuser", "registry_usrclass",
            "event_logs", "prefetch"]
  output_dir: "C:\\Vakalar"
  source_root: "C:\\ice_aktar\\2026-06-07T220139_user\\C"
```

Nasıl çalışır: katalogdaki her kalıp — ister `%SystemDrive%\$MFT` gibi bir
ortam değişkeni ister `C:\Users\*\NTUSER.DAT` gibi sabit bir sürücü harfi
kullansın — sürücü harfi çıkarılıp `source_root` altına yeniden
köklendirilir (bkz. `collection/selector.py::expand_pattern`). VSS
**hiçbir hedef için** açılmaz — `requires_vss: true` etiketi katalogda
KORUNUR (bulgu/rapor tarafında hâlâ anlamlı: "bu artefakt normalde kilitli
olurdu") ama collector.py bu modda hiç gölge kopya denemez, dosyalar
doğrudan okunur.

`route` (MFTECmd/RECmd/EvtxECmd/PECmd) ve sonraki tüm katmanlar (tespit,
raporlama) hiçbir değişiklik gerektirmeden çalışır — onlar zaten toplama
katmanının ÇIKTISI (vakanın kendi `artifacts/` klasörü) üzerinde
çalışıyor, verinin canlı mı yoksa içe aktarılmış mı olduğunu bilmeleri
gerekmiyor.

`additional_volumes` içe aktarma modunda **atlanır** (bir "ek birim"
kavramının tek bir içe aktarılmış makine ağacında karşılığı yok);
`suspicious_binaries` etkilenmez (zaten `source_root`'tan bağımsız,
analistin verdiği mutlak bir yol).

Gerçek bir KAPE çıktısına karşı doğrulandı: 384/384 dosya (SAM/SECURITY/
SYSTEM/SOFTWARE kovanları, 121 gerçek `.evtx`, gerçek prefetch dosyaları)
hatasız toplandı, `route` adımı gerçek MFTECmd/RECmd/EvtxECmd/PECmd ile
0 hatayla tamamlandı, `report` geçerli bir zincirle sonuçlandı — bkz.
`aldigim_kararlar.md` → "İçe aktarma modu".

## `custody`

| Anahtar | Tip | Zorunlu | Varsayılan | Anlamı |
|---|---|---|---|---|
| `log_path` | string (yol) veya `null` | Hayır | `null` | Gözetim zinciri defterinin yolu. `null` ise `<output_dir>/<case_id>/custody.jsonl` olarak türetilir. Türetme tek bir yerde, `config/loader.py` içindeki `resolve_custody_log_path()` fonksiyonunda yapılır. |

## `router`

`triagechain route` komutunun kullandığı ayrıştırma araçları. Bölümün tamamı
isteğe bağlıdır; hiç yazılmazsa her artefakt "araç konfigüre edilmemiş" diyerek
atlanır — bu bir hata değildir.

| Anahtar | Tip | Zorunlu | Varsayılan | Anlamı |
|---|---|---|---|---|
| `tools` | string → string sözlüğü | Hayır | `{}` | Araç adı → çalıştırılabilirin **mutlak** yolu. Araç adları `router/catalog/tool_mapping.yaml` içindeki `tool` değerleridir: `mftecmd`, `recmd`, `evtxecmd`, `pecmd`. Göreli yol yazılırsa `ConfigError` alırsınız (hangi ikilinin çalıştığı belirsizleşir, PATH-hijack riski). Dosyanın konfigürasyon yüklenirken var olması **gerekmez**; bulunamayan yol koşu anında "atlandı" olarak kaydedilir. |
| `recmd_batch_file` | string (yol) veya `null` | Hayır | `null` | RECmd'in `--bn` bayrağına verilecek toplu (batch) dosyasının **mutlak** yolu. `null` bırakılırsa pakete **gömülü** `DFIRBatch.reb` kullanılır — yani bu alanı hiç yazmasanız da RECmd çalışır. Değer verilirse mutlak olmak zorunda (`ConfigError`). Dosyanın konfigürasyon yüklenirken var olması gerekmez; bulunamayan yol koşu anında "atlandı" olarak kaydedilir. |
| `timeout_seconds` | tamsayı | Hayır | `300` | Tek bir araç çağrısının üst süresi. Aşılırsa süreç sonlandırılır ve `processing_error` yazılır; koşu bir sonraki artefaktla devam eder. |

Örnek (araçlar makineye özel olduğu için örnek konfigürasyonda yorum satırı
olarak durur):

```yaml
router:
  tools:
    mftecmd: "C:\\Tools\\EZTools\\MFTECmd.exe"
    recmd: "C:\\Tools\\EZTools\\RECmd\\RECmd.exe"
    evtxecmd: "C:\\Tools\\EZTools\\EvtxECmd\\EvtxECmd.exe"
    pecmd: "C:\\Tools\\EZTools\\PECmd.exe"
  # Sadece kendi toplu dosyanizi kullanmak isterseniz; bos birakilirsa
  # gomulu DFIRBatch.reb kullanilir.
  # recmd_batch_file: "C:\\Tools\\EZTools\\RECmd\\BatchExamples\\Kendi.reb"
  timeout_seconds: 300
```

### RECmd neden bir toplu dosyaya ihtiyaç duyar?

MFTECmd/EvtxECmd/PECmd'nin aksine RECmd, `-f <hive> --csv <dizin>` ile
çalışmaz: hangi anahtar/değerlerin çıkarılacağını **ayrıca** bilmek ister
(gerçek hata: `One of the following switches is required: --sa | --sk | ... |
--bn`). Triaj için doğru cevap `--bn <toplu dosya>`.

TriageChain bunu, `EricZimmerman/RECmd` deposundaki **MIT lisanslı**
`DFIRBatch.reb` dosyasının belirli bir sürüme **sabitlenmiş** bir kopyasını
pakete gömerek çözer:

```
src/triagechain/router/catalog/recmd_batch/DFIRBatch.reb
src/triagechain/router/catalog/recmd_batch/PROVENANCE.md   (kaynak, sürüm, git commit, SHA-256)
```

Sürüm bilerek sabitlenmiştir: RECmd'in kendi `--sync` bayrağı gibi "her
koşuda en güncelini indir" davranışı, aynı vakanın farklı zamanlarda farklı
kural setiyle farklı sonuç üretmesine — yani tekrarlanabilirliğin
kaybolmasına — yol açardı. Hangi toplu dosyanın kullanıldığı ve o dosyanın
SHA-256'sı, işlenen her artefakt için gözetim zincirine yazılır (bkz.
[chain_of_custody.md](chain_of_custody.md) → metodoloji izlenebilirliği).

Yönlendirme çıktısı:

```
<output_dir>/<case_id>/parsed/<arac>/<artifact_type_id>/       (aracın CSV çıktısı + .stdout.log/.stderr.log)
<output_dir>/<case_id>/routing_manifest.json
```

Araçlar (MFTECmd, RECmd, EvtxECmd, PECmd) TriageChain ile dağıtılmaz; ayrı
ayrı indirilen açık kaynak Eric Zimmerman araçlarıdır.

## `detection`

`triagechain detect` komutunun kullandığı Sigma kural tabanlı tespit motoru
(Hayabusa). `router` gibi bu bölümün tamamı da isteğe bağlıdır; yazılmazsa
tespit koşusu "araç konfigüre edilmemiş" diyerek atlanır — bu bir hata
değildir.

| Anahtar | Tip | Zorunlu | Varsayılan | Anlamı |
|---|---|---|---|---|
| `hayabusa_path` | string (yol) veya `null` | Hayır | `null` | Hayabusa çalıştırılabilirinin **mutlak** yolu. Göreli yol `ConfigError` üretir. Dosyanın konfigürasyon yüklenirken var olması gerekmez; bulunamayan yol koşu anında "atlandı" olarak kaydedilir. |
| `rules_dir` | string (yol) veya `null` | Hayır | `null` | Sigma kural klasörünün **mutlak** yolu — **hem Hayabusa HEM Chainsaw** bu AYNI klasörü kullanır (ayrı bir `chainsaw_rules_dir` YOK, bkz. aşağıdaki "Motor korelasyonu" bölümü). Kurallar TriageChain ile dağıtılmaz (RECmd toplu dosyasının aksine — o tek bir dosya, bu binlerce); Hayabusa sürümünüzle gelen `rules/` klasörünü gösterin. Boşsa ya da diskte yoksa tespit atlanır. Klasörün yapısal parmak izi gözetim zincirine yazılır (bkz. [chain_of_custody.md](chain_of_custody.md)). |
| `timeout_seconds` | tamsayı | Hayır | `600` | Tek bir `.evtx` taramasının üst süresi. Router'ın 300 saniyesinden uzun tutuldu: Hayabusa tüm bir olay günlüğünü binlerce kurala karşı tarar. Aşılırsa süreç sonlandırılır, `detection_error` yazılır ve koşu bir sonraki dosyayla devam eder. |
| `yara_path` | string (yol) veya `null` | Hayır | `null` | YARA çalıştırılabilirinin (`yara64.exe` vb.) **mutlak** yolu. Göreli yol `ConfigError` üretir. Hayabusa gibi TriageChain ile dağıtılmaz. |
| `yara_rules_file` | string (yol) veya `null` | Hayır | `null` | TEK bir `.yar`/`.yara` kural dosyasının **mutlak** yolu. Birden fazla kural isteniyorsa YARA'nın kendi `include` direktifi kullanılır — TriageChain ayrı bir kural-birleştirme mekanizması icat etmez. |
| `yara_timeout_seconds` | tamsayı | Hayır | `300` | Tek bir dosyanın YARA taramasının üst süresi. |
| `chainsaw_path` | string (yol) veya `null` | Hayır | `null` | Chainsaw çalıştırılabilirinin **mutlak** yolu. Göreli yol `ConfigError` üretir. Hayabusa gibi TriageChain ile dağıtılmaz. |
| `chainsaw_mapping_file` | string (yol) veya `null` | Hayır | `null` | Chainsaw'ın Sigma-alan-eşleme dosyasının (`sigma-event-logs-all.yml` vb., Chainsaw'ın kendi dağıtımıyla gelir) **mutlak** yolu. |
| `chainsaw_timeout_seconds` | tamsayı | Hayır | `600` | Tek bir `.evtx` taramasının üst süresi (Hayabusa'nın `timeout_seconds`'ıyla aynı gerekçe). |
| `capa_path` | string (yol) veya `null` | Hayır | `null` | capa çalıştırılabilirinin **mutlak** yolu. Göreli yol `ConfigError` üretir. Diğerleri gibi TriageChain ile dağıtılmaz. |
| `capa_rules_dir` | string (yol) veya `null` | Hayır | `null` | Özel bir capa kural klasörü — **ZORUNLU DEĞİL**: capa gömülü bir varsayılan kural setiyle kutudan çıktığı gibi çalışır, bu alan sadece bir override'dır. |
| `capa_timeout_seconds` | tamsayı | Hayır | `1800` | Tek bir dosyanın capa taramasının üst süresi. capa'nın statik analizi (disassembly) Hayabusa/Chainsaw/YARA'dan BELİRGİN şekilde daha yavaştır — gerçek bir notepad.exe'ye karşı ~43 saniye sürdü; büyük/paketlenmiş bir dosya dakikalar alabilir. |
| `watchlist_hashes_file` | string (yol) veya `null` | Hayır | `null` | Bilinen-kötü hash listesinin (watchlist/IOC) **mutlak** yolu. Diğerlerinin AKSİNE bir "araç yolu" DEĞİL: watchlist eşleştirmesi hiçbir dış program çalıştırmaz, toplama sırasında zaten hesaplanmış `hash_value`'lara karşı saf Python karşılaştırması yapar (bkz. aşağıdaki watchlist bölümü). |

Yalnızca `artifact_type_id == "event_logs"` olan artefaktlar Hayabusa/
Chainsaw ile taranır; ikisi de Windows olay günlüğü tarayıcısıdır, registry
kovanı ya da prefetch okumaz. **YARA farklı**: statik imza taraması herhangi
bir dosya formatında anlamlı olduğu için toplanan HER artefakt türü YARA'ya
gönderilir (bkz. aşağıdaki YARA bölümü). **capa da farklı**: sadece
`collection.suspicious_binaries`'daki dosyalar (`artifact_type_id ==
"suspicious_binary"`) taranır — analistin elle işaret ettiği dosyalar
dışında hiçbir şey capa'ya gönderilmez (bkz. aşağıdaki capa bölümü).
**watchlist de YARA gibi** toplanan HER artefaktı karşılaştırır, ama hiçbir
harici araç çağırmaz (bkz. aşağıdaki watchlist bölümü).

Örnek:

```yaml
detection:
  hayabusa_path: "C:\\Tools\\hayabusa\\hayabusa.exe"
  rules_dir: "C:\\Tools\\hayabusa\\rules"
  timeout_seconds: 600
  yara_path: "C:\\Tools\\yara\\yara64.exe"
  yara_rules_file: "C:\\Tools\\yara\\rules\\benim_kurallarim.yar"
  yara_timeout_seconds: 300
  chainsaw_path: "C:\\Tools\\chainsaw\\chainsaw.exe"
  chainsaw_mapping_file: "C:\\Tools\\chainsaw\\mappings\\sigma-event-logs-all.yml"
  chainsaw_timeout_seconds: 600
  capa_path: "C:\\Tools\\capa\\capa.exe"
  capa_timeout_seconds: 1800
  watchlist_hashes_file: "C:\\Vaka\\bilinen-kotu-hashler.txt"
```

`watchlist_hashes_file` biçimi: satır başına bir girdi, `hash` ya da
`hash,etiket` ya da `hash etiket` (virgül veya boşluk ile ayrılmış). `#` ile
başlayan ve boş satırlar yok sayılır. Hash'ler büyük/küçük harf duyarsız
karşılaştırılır. Örnek:

```
# Bilinen kötü araçlar
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,Mimikatz derlemesi
5d41402abc4b2a76b9719d911017c592,başka bir IOC
```

Tespit çıktısı:

```
<output_dir>/<case_id>/detections/hayabusa/<dosya>.hayabusa.csv   (Hayabusa'nın ham CSV'si)
<output_dir>/<case_id>/detections/hayabusa/<dosya>.stdout.log
<output_dir>/<case_id>/detections/hayabusa/<dosya>.stderr.log
<output_dir>/<case_id>/detection_manifest.json                    (ayrıştırılmış bulgular)
```

Hayabusa'nın komut satırı sözdizimi ve CSV sütun adları koda gömülü değildir;
`detection/catalog/hayabusa_args.yaml` içinde veri olarak durur. Sürüm farkı
nedeniyle çağrı ya da başlık eşlemesi tutmazsa **Python değiştirmeden** bu
dosya düzeltilir (bkz. [hatalar_ve_sonuclar.md](hatalar_ve_sonuclar.md) →
operasyonel notlar). Sigma kurallarının kendi metadatasındaki MITRE ATT&CK
etiketleri (Hayabusa `MitreTactics` sütunu üretirse) `Finding.mitre_tags`'e
aynen yansır — yeni bir veri kaynağı/ağ çağrısı DEĞİL.

### YARA (`triagechain yara-scan`)

Hayabusa'dan ayrı, ikinci bir tespit motoru: `detection/yara_runner.py`,
Hayabusa ile BİREBİR aynı güvenlik kurallarını (subprocess listesi, asla
`shell=True`, mutlak yollar, zaman aşımı) izler. Fark: YARA sonucu bir CSV
dosyasına değil doğrudan stdout'a yazar, bu yüzden ayrı bir çıktı dosyası
yoktur:

```
<output_dir>/<case_id>/detections/yara/<dosya>.stdout.log
<output_dir>/<case_id>/detections/yara/<dosya>.stderr.log
<output_dir>/<case_id>/yara_manifest.json
```

Argüman şablonu ve stdout satır deseni `detection/catalog/yara_args.yaml`
içinde veri olarak durur (gerçek `yara64.exe 4.5.5`'e karşı doğrulandı, bkz.
`hatalar_ve_sonuclar.md`). YARA kural dosyası TriageChain ile
**dağıtılmaz** (açık kaynak kural setlerinin çoğu GPL/DRL gibi kısıtlayıcı
lisanslarla geliyor — bkz. `aldigim_kararlar.md`); kendi `.yar` dosyanızı
yazıp `yara_rules_file` ile gösterin.

### Chainsaw (`triagechain chainsaw-scan`)

Hayabusa'dan ayrı, BAĞIMSIZ bir Sigma motoru: `detection/chainsaw_runner.py`,
Hayabusa'nın izlediği aynı güvenlik kurallarına (subprocess listesi, asla
`shell=True`, mutlak yollar, zaman aşımı) uyar. En önemli fark: Chainsaw
`chainsaw_rules_dir` gibi kendine ait bir kural klasörü kullanmaz —
yukarıdaki `detection.rules_dir`'i Hayabusa ile AYNEN paylaşır, çünkü amaç
"iki farklı kural setiyle ne bulunuyor" değil, "aynı kural setiyle iki
bağımsız motor aynı sonuca varıyor mu" sorusudur (bkz. `aldigim_
kararlar.md`). Çıktısı, Hayabusa'nınkiyle AYNI `Finding` şemasını üretir
ama ayrı bir dosyaya yazılır:

```
<output_dir>/<case_id>/detections/chainsaw/<dosya>.chainsaw.json
<output_dir>/<case_id>/detections/chainsaw/<dosya>.stdout.log
<output_dir>/<case_id>/detections/chainsaw/<dosya>.stderr.log
<output_dir>/<case_id>/chainsaw_manifest.json
```

Argüman şablonu ve JSON alan eşlemesi `detection/catalog/chainsaw_args.yaml`
içinde veri olarak durur (gerçek Chainsaw v2.16.5'e karşı, EVTX-ATTACK-
SAMPLES + SigmaHQ ile gerçek bir tarama çalıştırılarak doğrulandı). Chainsaw
kendisi de TriageChain ile **dağıtılmaz** — kendi ikilinizi indirip
`chainsaw_path` ile gösterin; `chainsaw_mapping_file` Chainsaw'ın kendi
dağıtımıyla gelen Sigma-alan-eşleme dosyasını (`sigma-event-logs-all.yml`
vb.) gösterir.

### capa (`triagechain capa-scan`)

Hayabusa/Chainsaw/YARA'dan tamamen farklı bir soru soran, ayrı bir motor:
`detection/capa_runner.py`, `collection.suspicious_binaries`'daki
(analistin elle gösterdiği şüpheli `.exe`/`.dll` dosyaları) her birini
capa (Mandiant/FLARE) ile davranış/yetenek analizine tabi tutar. AYNI yedi
güvenlik kuralı geçerlidir (`shell=True` yok, mutlak yol, vakanın kendi
ağacı, zaman aşımı). SADECE `artifact_type_id == "suspicious_binary"`
olan artefaktlar taranır — Hayabusa'nın "sadece event_logs" kısıtıyla aynı
ilke, ama farklı bir artefakt türü için.

Veri modeli Finding/DetectionManifest DEĞİL, **YARA'nın `YaraMatch`/
`YaraManifest` şeması yeniden kullanılır** — capa da (YARA gibi) TEK bir
dosyaya karşı çalışıp adlandırılmış kural eşleşmeleri üretir, olay-tabanlı
bir zaman/bilgisayar/kanal bağlamı yoktur. `rule_name` = capa kural adı,
`tags` = MITRE ATT&CK id'leri (kuralın kendi `meta.attack` alanından,
virgülle birleştirilmiş), `meta` = `namespace=<capa namespace'i>`.

```
<output_dir>/<case_id>/detections/capa/<dosya>.stdout.log
<output_dir>/<case_id>/detections/capa/<dosya>.stderr.log
<output_dir>/<case_id>/capa_manifest.json
```

capa'nın diğerlerinden en önemli farkı: **gömülü bir varsayılan kural
setiyle kutudan çıktığı gibi çalışır**, `capa_rules_dir` ZORUNLU değildir
(sadece bir override). Bu yüzden "araç konfigüre edilmemiş" atlama mantığı
SADECE `capa_path` için geçerlidir.

**capa Yönetici Raporu'nun risk hesabına BİLEREK KATILMAZ.** capa bir
binary'nin NELER YAPABİLECEĞİNİ listeler (statik yetenek envanteri), bir
Sigma/YARA kuralının aksine "bu davranış kötü amaçlı" demez — gerçek,
zararsız bir `.exe`'de bile onlarca capa kuralı eşleşir (bkz. gerçek
notepad.exe testinde 35 eşleşme, hepsi sıradan yetenekler). Bu yüzden
capa+YARA arasında bir korelasyon de ÜRETİLMEZ (bilinçli bir kapsam
sınırı, gerekçesi `aldigim_kararlar.md`'de).

### Hash listesi / watchlist (`triagechain watchlist-check`)

Diğer dört motordan (Hayabusa/Chainsaw/YARA/capa) TEMEL mimari farkı:
`detection/watchlist_runner.py` hiçbir DIŞ ARAÇ/subprocess çağırmaz —
toplama sırasında zaten hesaplanmış `CollectedArtifact.hash_value`'lara
karşı SAF PYTHON sözlük karşılaştırması yapar. Bu yüzden mutlak araç yolu,
zaman aşımı, stdout/stderr log dosyası gibi kavramlar burada YOK; tek
gereksinim `detection.watchlist_hashes_file`'ın (yukarıda) gösterdiği
listedir.

YARA ile ortak noktası: toplanan HER artefakt türü karşılaştırılır (capa'nın
"sadece şüpheli binary" kısıtı YOK). Veri modeli de YARA'nın kullandığı
`YaraMatch`/`YaraManifest` şeması — bir eşleşme `rule_name = "watchlist:
<etiket>"`, `tags = "watchlist"`, `meta = "hash_algorithm=<algoritma>"`
taşır.

```
<output_dir>/<case_id>/watchlist_manifest.json
```

**capa'nın AKSİNE watchlist Yönetici Raporu'nun risk hesabına KATILIR** ve
EN GÜÇLÜ sinyaldir (`reporting/executive.py`): bilinen-kötü bir hash'e TAM
eşleşme, bir Sigma/YARA kuralının sezgisel eşleşmesinden farklı olarak
pratikte yanlış-pozitif üretmez — bu yüzden ≥1 eşleşme doğrudan "Kritik"
risk seviyesine yükseltir (korelasyon/motor ittifakıyla AYNI seviyede).

### Motor korelasyonu

Hem Hayabusa (`detection_manifest.json`) HEM YARA (`yara_manifest.json`)
çalıştırılmışsa, `triagechain report` ikisinin de AYNI dosyayı
işaretlediği durumları `detection/correlation.py::correlate_findings` ile
buluyor ve rapora (`Report.correlated_artifacts`, hem JSON hem HTML)
ekliyor — iki bağımsız tekniğin aynı sonuca varması, tek başına bir
bulgudan daha güçlü bir sinyal sayılır.

Hem Hayabusa HEM Chainsaw çalıştırılmışsa, `correlate_sigma_engines` AYNI
mantıkla `(source_path, rule_title)` eşitliğini arıyor ve sonucu
`Report.engine_agreements`'a (hem JSON hem HTML — "Motor ittifakı"
bölümü) yazıyor. Yönetici Raporu'nun risk kuralı (`reporting/
executive.py`) her iki korelasyonu da (Sigma+YARA VE Hayabusa+Chainsaw)
AYNI önemde ("Kritik") sayıyor.

## Rapor çıktısı (`triagechain report`)

Raporlamanın **kendine ait bir konfigürasyon bölümü yoktur**: bilmesi gereken
her şey (vaka bilgisi, çıktı kökü, custody defterinin yeri) zaten `case`,
`collection` ve `custody` bölümlerinde tanımlı. Komut yalnızca bu bölümlerdeki
yollardan türetilen dosyaları okur ve üç yeni dosya yazar:

```
<output_dir>/<case_id>/report.json           (makine-okur rapor)
<output_dir>/<case_id>/report.json.sha256    ("<hash>  report.json" - sha256sum ile doğrulanabilir)
<output_dir>/<case_id>/report.html           (insan-okur, tek sayfa, tamamen offline)
```

Okuduğu girdiler:

| Dosya | Zorunlu mu | Yoksa ne olur |
|---|---|---|
| `manifest.json` | Evet | Komut `Toplama manifesti yok ...` mesajıyla **çıkış kodu 2** ile durur. |
| `custody.jsonl` | Evet | `CustodyLedgerError` (manifest varken defterin olmaması zincirin kaybı demektir). |
| `routing_manifest.json` | Hayır | Raporun yönlendirme bölümü "henüz çalıştırılmadı" der. |
| `detection_manifest.json` | Hayır | Raporun tespit (Sigma/Hayabusa) bölümü "henüz çalıştırılmadı" der. |
| `yara_manifest.json` | Hayır | Raporun YARA bölümü "henüz çalıştırılmadı" der; ikisi de yoksa Sigma+YARA korelasyon bölümü hiç görünmez. |
| `chainsaw_manifest.json` | Hayır | Raporun Chainsaw bölümü "henüz çalıştırılmadı" der; `detection_manifest.json` ile ikisi de yoksa "Motor ittifakı" bölümü hiç görünmez. |
| `capa_manifest.json` | Hayır | Raporun capa bölümü "henüz çalıştırılmadı" der. Hiçbir korelasyon/risk hesabını etkilemez (bkz. yukarıdaki capa bölümü). |

Çıkış kodları: rapor üretilemezse `1` (`ReportingError`, örn. disk dolu/izin
yok), toplama manifesti hiç yoksa `2`. Rapor üretilse **bile** gözetim zinciri
o an geçersizse komut `1` döndürür (`verify-custody` ile aynı davranış) — rapor
yine de diske yazılır ve durumu "GEÇERSİZ" olarak gösterir.

`report.html` iki sekmeye ayrılır (saf CSS ile, JS/kütüphane yok — internetsiz
bir makinede de tıklanabilir): **Yönetici Raporu** (teknik olmayan, Report'un
gerçek sayılarından deterministik bir kurala göre hesaplanan risk seviyesi +
düz metin özet — bkz. `reporting/executive.py`) ve **Uzman Raporu** (eskiden
beri var olan teknik detay: toplama/yönlendirme/tespit/Chainsaw/YARA/capa
özetleri, tam bulgu tabloları, korelasyon + motor ittifakı bölümleri,
gözetim zincirinin tam olay listesi).

## `logging`

| Anahtar | Tip | Zorunlu | Varsayılan | Anlamı |
|---|---|---|---|---|
| `level` | `CRITICAL` \| `ERROR` \| `WARNING` \| `INFO` \| `DEBUG` \| `NOTSET` | Hayır | `INFO` | Uygulama günlüğü seviyesi. Gözetim zinciri defterini etkilemez; o her koşulda yazılır. |

## Doğrulama hataları

Tüm konfigürasyon sorunları tek bir hata tipiyle, `ConfigError` ile bildirilir.
Pydantic'in ham hata metni kullanıcıya gösterilmez; alan adı ve sorun kısaca
özetlenir. Örnek:

```
Konfigurasyon gecersiz (config.yaml): collection.targets: Value error,
katalogda olmayan hedef kimlikleri: hayali_hedef
```
