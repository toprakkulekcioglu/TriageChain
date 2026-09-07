# Chain of Custody (gözetim zinciri)

TriageChain, toplama sırasındaki her önemli olayı yalnızca **ekleme yapılan**
(append-only) bir JSONL defterine yazar. Her kayıt bir öncekinin hash'ine
bağlıdır; dolayısıyla defterdeki tek bir karakteri bile değiştirmek zinciri
kırar ve doğrulama sırasında hangi kayıtta kırıldığı raporlanır.

Bu belge, şemayı bağımsız bir araçla yeniden uygulayıp doğrulamaya yetecek
kadar kesin tanımlar.

## Kayıt biçimi

Defter (`custody.jsonl`) satır başına bir JSON nesnesi içerir. Alanlar:

| Alan | Tip | Açıklama |
|---|---|---|
| `event_id` | string | Olay için üretilmiş uuid4 |
| `timestamp_utc` | string | UTC, ISO-8601 (`2026-01-02T03:04:05.678901+00:00`) |
| `event_type` | string | Aşağıdaki tabloda listelenen olay tiplerinden biri |
| `case_id` | string | Vaka kimliği |
| `operator` | string | Konfigürasyonda bildirilen operatör |
| `payload` | object | Olaya özgü alanlar; **her zaman** `tsa_token` anahtarını içerir (şimdilik `null`) |
| `prev_hash` | string | Bir önceki kaydın `entry_hash`'i (ilk kayıtta genesis hash) |
| `entry_hash` | string | Bu kaydın hash'i |

## Olay tipleri

Toplama (faz 1), yönlendirme (faz 2), tespit (faz 4, Hayabusa) ve bu
katmandan sonra eklenen YARA/Chainsaw taramaları **aynı deftere**, aynı
zincire yazar: bir vaka için tek bir `custody.jsonl` vardır, `route` /
`detect` / `yara-scan` / `chainsaw-scan` komutları zinciri kaldığı yerden
devam ettirir.

| `event_type` | Katman | Ne zaman yazılır |
|---|---|---|
| `case_opened` | toplama | Toplama koşusu başladı |
| `artifact_collected` | toplama | Bir dosya alındı ve hash'i doğrulandı |
| `collection_error` | toplama | Tek bir artefakt alınamadı (ölümcül değil) |
| `integrity_error` | toplama | Yazılan kopyanın hash'i tutmadı (**ölümcül**) |
| `case_closed` | toplama | Toplama koşusu bitti |
| `routing_started` | yönlendirme | Yönlendirme koşusu başladı; yükte `run_id`, `collection_run_id`, `artifact_count` |
| `artifact_processed` | yönlendirme | Bir artefakt bir dış araçla başarıyla ayrıştırıldı; yükte `tool`, `source_path`, `output_dir`, `exit_code`, `stdout_log_path`, `stderr_log_path`, `duration_seconds` — RECmd ile işlenmişse ayrıca `recmd_batch_path` ve `recmd_batch_sha256` (bkz. aşağıdaki metodoloji bölümü) |
| `processing_skipped` | yönlendirme | Artefakt atlandı: tanımlı araç yok, araç konfigüre edilmemiş ya da araç yolu diskte bulunamadı (ölümcül değil) |
| `processing_error` | yönlendirme | Araç sıfırdan farklı kod döndürdü (`stderr_excerpt` ile), zaman aşımına uğradı ya da girdi yolu çıktı ağacının dışında kaldı (ölümcül değil) |
| `routing_completed` | yönlendirme | Yönlendirme koşusu bitti; yükte `processed_count`, `skipped_count`, `error_count` |
| `detection_started` | tespit | Tespit koşusu başladı; yükte `run_id`, `collection_run_id`, taranacak `.evtx` sayısı — kural klasörü tanımlıysa ve diskte varsa ayrıca `rules_dir`, `rules_file_count`, `rules_fingerprint_sha256` (bkz. aşağıdaki metodoloji bölümü) |
| `detection_completed_for_artifact` | tespit | Bir olay günlüğü tarandı; yükte `source_path`, `output_csv_path`, `finding_count`, `level_counts` (seviyeye göre dağılım), `duration_seconds`, varsa `parse_warning` |
| `detection_skipped` | tespit | Tarama atlandı: Hayabusa ya da kural klasörü konfigüre edilmemiş veya diskte bulunamadı (ölümcül değil); yükte kaç dosyanın etkilendiği |
| `detection_error` | tespit | Hayabusa sıfırdan farklı kod döndürdü (`stderr_excerpt` ile), zaman aşımına uğradı ya da girdi yolu çıktı ağacının dışında kaldı (ölümcül değil) |
| `detection_completed` | tespit | Tespit koşusu bitti; yükte `scanned_count`, `finding_count`, `skipped_count`, `error_count`, `detection_manifest_path` ve **`detection_manifest_sha256`** |
| `yara_started` | YARA | YARA koşusu başladı; yükte `run_id`, `collection_run_id`, `artifact_count` — kural dosyası tanımlıysa ayrıca `yara_rules_file`, `yara_rules_sha256` (TEK dosya, tam içerik hash'i — Hayabusa'nın klasör parmak izinden farklı, bkz. aşağıdaki metodoloji bölümü) |
| `yara_completed_for_artifact` | YARA | Bir artefakt tarandı; yükte `artifact_type_id`, `source_path`, `match_count`, `duration_seconds` |
| `yara_skipped` | YARA | Tarama atlandı: YARA ya da kural dosyası konfigüre edilmemiş/diskte yok (ölümcül değil) |
| `yara_error` | YARA | YARA sıfırdan farklı kod döndürdü ya da zaman aşımına uğradı (ölümcül değil) |
| `yara_completed` | YARA | YARA koşusu bitti; yükte `scanned_count`, `match_count`, `skipped_count`, `error_count`, `yara_manifest_path`, `yara_manifest_sha256` |
| `chainsaw_started` | Chainsaw | Chainsaw koşusu başladı; yükte `run_id`, `collection_run_id`, `artifact_count` (Hayabusa ile AYNI `detection.rules_dir`'i kullandığı için ayrı bir kural-klasörü parmak izi TAŞIMAZ — o zaten `detection_started` olayında var) |
| `chainsaw_completed_for_artifact` | Chainsaw | Bir olay günlüğü tarandı; yükte `source_path`, `finding_count`, `duration_seconds` |
| `chainsaw_skipped` | Chainsaw | Tarama atlandı: Chainsaw, kural klasörü ya da eşleme dosyası konfigüre edilmemiş/diskte yok (ölümcül değil) |
| `chainsaw_error` | Chainsaw | Chainsaw sıfırdan farklı kod döndürdü ya da zaman aşımına uğradı (ölümcül değil) |
| `chainsaw_completed` | Chainsaw | Chainsaw koşusu bitti; yükte `scanned_count`, `finding_count`, `skipped_count`, `error_count`, `chainsaw_manifest_path`, `chainsaw_manifest_sha256` |
| `capa_started` | capa | capa koşusu başladı; yükte `run_id`, `collection_run_id`, `artifact_count` (SADECE `suspicious_binary` türündeki artefaktlar sayılır) |
| `capa_completed_for_artifact` | capa | Bir şüpheli dosya tarandı; yükte `source_path`, `match_count` (eşleşen yetenek sayısı), `duration_seconds` |
| `capa_skipped` | capa | Tarama atlandı: capa konfigüre edilmemiş/diskte yok (ölümcül değil) — `capa_rules_dir` ayarlanmışsa ve diskte yoksa da atlanır, ama ayarlanmamışsa hiç kontrol edilmez (gömülü kurallar kullanılır) |
| `capa_error` | capa | capa sıfırdan farklı kod döndürdü ya da zaman aşımına uğradı (ölümcül değil) |
| `capa_completed` | capa | capa koşusu bitti; yükte `scanned_count`, `match_count`, `skipped_count`, `error_count`, `capa_manifest_path`, `capa_manifest_sha256` |

Atlama ve işleme hataları da deftere yazılır: bir artefaktın **neden**
ayrıştırılmadığı/taranmadığı da zincirin parçasıdır, sessizce düşürülmez.

YARA, Chainsaw ve capa, tespit (Hayabusa) katmanıyla AYNI ilkeyi izler:
bulgu başına değil, taranan artefakt/dosya başına tek bir özet olay
yazılır; bulguların/eşleşmelerin kendisi yalnızca `yara_manifest.json`/
`chainsaw_manifest.json`/`capa_manifest.json` içindedir ve bütünlükleri o
dosyaların SHA-256'sının `*_completed` olayına işlenmesiyle zincire
bağlanır (bkz. aşağıdaki "Tespit bulguları neden deftere tek tek
yazılmaz?" bölümü — aynı gerekçe YARA/Chainsaw/capa için de geçerlidir).

## Raporlama (faz 5) deftere hiçbir şey yazmaz

`triagechain report` bu tablodaki hiçbir olayı üretmez; defteri yalnızca
**okur** (`read_events` + `verify_chain`) ve gördüğünü rapora aktarır. Rapor,
zincirin üretim anındaki fotoğrafıdır: kendisi bir olay yazsaydı, rapordaki
olay listesi ve zincir doğrulama sonucu daha yazıldığı anda eskimiş olurdu.
Diğer üç katman delil üzerinde işlem yaptığı için deftere yazar, raporlama
hiçbir delile dokunmaz.

Raporun kendisinin sonradan değişip değişmediği zincirden değil, yanına
yazılan `report.json.sha256` dosyasından kontrol edilir (bkz.
[config_reference.md](config_reference.md) → rapor çıktısı).

## Tespit bulguları neden deftere tek tek yazılmaz?

Bir tek `.evtx` binlerce Sigma bulgusu üretebilir. Gözetim zinciri "kim, ne
zaman, neyi işledi" sorusunun kanıtıdır; analiz çıktısının deposu değildir.
Bu yüzden defterde **taranan dosya başına tek bir özet olay** durur (bulgu
sayısı ve seviye dağılımı), bulguların kendisi yalnızca
`detection_manifest.json` içindedir.

Detayların bütünlüğü yine de zincire bağlıdır: koşu biterken manifest önce
diske yazılır, sonra SHA-256'sı `detection_completed` olayının yüküne
işlenir. Manifest sonradan değiştirilirse hash tutmaz; hash'in kendisi de
zincirin parçası olduğu için deftere geri dönüp düzeltmek zinciri kırar.

## Metodoloji izlenebilirliği: hangi kural seti kullanıldı?

Adli bilişimde bir bulgu sorgulandığında sorulacak ilk sorulardan biri "bu
sonucu tam olarak hangi kural/metodoloji seti üretti" olur. Bu yüzden defter,
işlemin *kim/ne zaman/neyi* bilgisine ek olarak **hangi kural setiyle**
bilgisini de taşır. İki araçta iki farklı biçimde:

### RECmd toplu (batch) dosyası — tam içerik hash'i

`artifact_processed` olayı, artefakt RECmd ile işlendiyse iki alan daha
taşır:

| Alan | Anlamı |
|---|---|
| `recmd_batch_path` | `--bn` ile verilen toplu dosyanın yolu (config'deki `router.recmd_batch_file` ya da pakete gömülü `DFIRBatch.reb`) |
| `recmd_batch_sha256` | O dosyanın **içeriğinin** SHA-256'sı (`collection/hashing.py` → `hash_file`) |

Toplu dosya tek bir dosya olduğu için burada tam ve kesin bir içerik hash'i
alınabiliyor: dosyada tek bir karakter değişse hash değişir. Diğer araçlarda
(MFTECmd, EvtxECmd, PECmd) ayrı bir kural dosyası kavramı olmadığı için bu
iki alan **hiç yazılmaz**.

### Hayabusa Sigma kural klasörü — yapısal parmak izi (sınırlı)

`rules_dir` bir dosya değil, binlerce Sigma kuralı içerebilen bir **klasör**.
Her koşuda tüm bu dosyaların içeriğini okuyup hash'lemek anlamsız bir maliyet
olurdu; bunun yerine `detection_started` olayı bir **yapısal parmak izi**
taşır:

| Alan | Anlamı |
|---|---|
| `rules_dir` | Kullanılan kural klasörünün yolu |
| `rules_file_count` | Klasördeki toplam dosya sayısı (alt klasörler dahil, recursive) |
| `rules_fingerprint_sha256` | Klasördeki tüm dosyaların `(göreli yol, boyut)` çiftlerinin **sıralı** listesinden hesaplanan tek bir SHA-256 |

**Bu parmak izinin sınırı açıkça bilinmelidir:**

- **Yakalar:** dosya eklenmesi, dosya çıkarılması, yeniden adlandırma, bir
  dosyanın boyutunun değişmesi.
- **YAKALAMAZ:** bir kural dosyasının içeriğinin **aynı boyutta kalacak
  şekilde** değiştirilmesi.

Yani bu alan, "kural setim iki koşu arasında güncellendi mi / aynı setle mi
çalıştım" sorusuna cevap veren operasyonel bir kayıttır; gizlemeye çalışan
bir saldırgana karşı kriptografik bir garanti değildir. Bu bilinçli bir
tradeoff'tur (bkz. [aldigim_kararlar.md](aldigim_kararlar.md)).

Kural klasörü hiç tanımlanmamışsa ya da diskte yoksa bu üç alan **hiç
yazılmaz** — uydurma bir değer (örneğin `rules_file_count: 0`) yazılmaz,
çünkü boş bir kural klasörü ile hiç kontrol edilememiş bir klasör adli açıdan
aynı şey değildir. Koşunun neden atlandığı zaten `detection_skipped`
olayında durur.

## Kanonik JSON kuralı

Hash her zaman **kanonik** gösterim üzerinden alınır:

- anahtarlar alfabetik sıralı (`sort_keys=True`),
- ayıraçlar boşluksuz: `(",", ":")`,
- UTF-8 kodlama, Unicode karakterler kaçışsız (`ensure_ascii=False`),
- `timestamp_utc` UTC'ye çevrilmiş ISO-8601 metni olarak yazılır.

Bu kural değişirse geçmiş defterlerin tamamı doğrulanamaz hale gelir; bu yüzden
şemanın sabit parçası sayılmalıdır.

## Genesis hash

Her vakanın zinciri, o vakaya özgü sabit bir değerle başlar:

```
genesis_hash = SHA256( case_id + "::TRIAGECHAIN_GENESIS" )
```

Örnek (Python):

```python
import hashlib
hashlib.sha256(("CASE-2026-001" + "::TRIAGECHAIN_GENESIS").encode()).hexdigest()
```

Defterdeki **ilk** kaydın `prev_hash` alanı tam olarak bu değer olmalıdır.
Böylece bir vakanın ilk kayıtlarını silip zinciri baştan kurmak, vaka kimliği
sabit kaldığı sürece fark edilir.

## Kayıt hash'i

```
entry_hash = SHA256( prev_hash_utf8_bytes + canonical_json_bytes(kayıt - entry_hash) )
```

Burada `kayıt - entry_hash`, kaydın `entry_hash` **dışındaki** tüm alanlarıdır
(dairesellik olmasın diye). Yani hash'lenen nesne şu yedi alandan oluşur:
`event_id`, `timestamp_utc`, `event_type`, `case_id`, `operator`, `payload`,
`prev_hash`.

`prev_hash`ın hem hash girdisinin başına ham olarak eklenmesi hem de kanonik
JSON'un içinde yer alması bilinçlidir: kayıtları yeniden sıralamak her iki
yoldan da tespit edilir.

## Doğrulama algoritması

`verify_chain(log_path, case_id)` şunu yapar:

1. `expected_prev = genesis_hash(case_id)`
2. Defterdeki her satır için sırayla:
   - satır JSON olarak çözülemiyorsa: geçersiz, dur;
   - `case_id` beklenenden farklıysa: geçersiz, dur;
   - `prev_hash != expected_prev` ise: geçersiz, dur (kayıt eklenmiş, silinmiş
     veya yeri değişmiş);
   - `entry_hash` yeniden hesaplanır; tutmuyorsa: geçersiz, dur (kayıt içeriği
     değiştirilmiş);
   - `expected_prev = entry_hash`.
3. Tüm satırlar geçtiyse zincir geçerlidir.

Sonuç `VerificationResult` olarak döner: `is_valid`, `total_events`,
`broken_at_event_id`, `message`. Doğrulama **ilk** uyuşmazlıkta durur ve hangi
olayda kırıldığını bildirir; "geçersiz" deyip susmaz.

## Neyi garanti eder, neyi etmez

Garanti eder: defter yazıldıktan sonra yapılan sessiz değişiklikler (içerik
değiştirme, satır silme, satır ekleme, sıra değiştirme) tespit edilir.

Garanti etmez: defterin tamamına erişebilen bir saldırgan, zinciri baştan
yeniden üretebilir — çünkü şema anahtarsızdır (HMAC ya da imza yoktur). Bunun
karşılığı, defterin toplama anında harici/salt-okunur bir ortama kopyalanması
veya ileride `payload.tsa_token` alanına bir zaman damgası otoritesi token'ının
yazılmasıdır. Bu alan tam da bu amaçla, şimdilik `null` olarak ayrılmıştır.

## Çoklu-yazıcı desteği (tamamlandı)

`custody/storage.py`'deki `locked(log_path)` context manager'ı,
`<log_path>.lock` dosyası üzerinden **süreçler arası** bir kilit kurar
(Windows'ta `msvcrt.locking`, POSIX'te `fcntl.flock` — ikisi de stdlib,
yeni bağımlılık yok). `CustodyLedger.append_event()` artık "son hash'i
oku → yeni kaydı ekle" ikilisini bu kilidin içinde, **atomik** olarak
yapıyor. Böylece aynı vaka için birden fazla süreç (örn. aynı anda
`yara-scan` VE `chainsaw-scan` çalıştırılması) deftere güvenle
yazabiliyor — 8 eşzamanlı yazıcıyla gerçek bir çatallanma senaryosu test
edildi (bkz. `aldigim_kararlar.md`). Defterin **okunması**
(`read_events`/`verify_chain`) kasıtlı olarak kilitsiz kaldı: okuma
sırasında yeni bir satır eklenmesi zaten append-only olduğu için mevcut
satırları etkilemez.
