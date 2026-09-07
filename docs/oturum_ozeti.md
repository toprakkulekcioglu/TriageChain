# Bu oturumda yapılanlar — özet

## 1. Proje fikri netleştirildi, mimari tasarlandı

TriageChain fikri (KAPE + Eric Zimmerman Tools + Hayabusa'yı tek pipeline'da
birleştirmek) baştan sona konuşuldu. İlk aşama olarak sadece **toplama
katmanı** ve **chain-of-custody** modülünün yapılmasına, format
dönüştürme/router'a henüz geçilmemesine karar verildi. Bir mimar ajanına
(Software Architect) tam bir tasarım hazırlatıldı: klasör yapısı, hash-zincir
şeması, config şablonu.

## 2. Bir yanlış varsayım düzeltildi: KAPE açık kaynak değil

"KAPE zaten açık kaynaklı, hepsini oradan çekelim" önerisi geldi ama bu
yanlıştı — KAPE (Kroll) ücretsiz ama **kapalı kaynak**, kendi EULA'sıyla
dağıtılıyor. Çözüm olarak KAPE'nin *kendisi* değil, açık kaynaklı hedef
tanımları (`EricZimmerman/KapeFiles` deposu) referans alındı — sadece "hangi
artefakt nerede durur" bilgisi kullanıldı, KAPE.exe'ye hiç bağımlılık
oluşmadı. Bu netleşme sonrası mimari onaylandı.

## 3. Faz 1 implementasyonu: toplama + chain-of-custody

Onaylanan mimariye göre tam proje iskeleti kuruldu:
`C:\Users\yasar\Desktop\TriageChain`. VSS erişimi `pywin32` yerine
`vssadmin` subprocess çağrısıyla, config doğrulama `pydantic` ile, katalog
YAML veri dosyası olarak. 24 test yazıldı, hepsi geçti. En kritik iki dosyayı
(`hashing.py`, `custody/ledger.py`) bizzat okuyup hash-zincir formülünün
tasarıma birebir uyduğunu doğruladım.

## 4. Basit çalıştırma arayüzü eklendi

`triagechain-gui` — sadece stdlib `tkinter` (yeni bağımlılık yok). Vaka
bilgisi, hedef seçimi, ayarlar, config yükle/kaydet, toplama (arka planda,
arayüz donmadan) ve zincir doğrulama. Görsel tasarım bilinçli olarak sade
bırakıldı; "profesyonel görünüm" ayrı bir aşamaya ertelendi. Pencereyi hiç
göstermeden (`root.withdraw()`) tüm widget'ların kurulduğu doğrulandı, ama
gerçek görsel görünüm kullanıcı tarafından kontrol edilmeli.

## 5. Faz 2: format dönüştürme / router katmanı

Roadmap'teki bir sonraki adıma geçildi: toplanan dosyaları
MFTECmd/RECmd/EvtxECmd/PECmd'ye yönlendiren router katmanı. Güvenlik
gereksinimleri baştan net konuldu: `shell=True` yasak, araç yolları mutlak
olmalı, girdi yolu vakanın kendi çıktı ağacı dışındaysa hiçbir şey
çalıştırılmamalı, her çağrının zaman aşımı olmalı. 13 yeni test (toplamda
37) — hepsi gerçek EZ Tools ikilisi olmadan, `subprocess.run` mock'lanarak.

## 6. İncelemede bulunan eksik: ham hata sızıntısı

Router kodunu incelerken, çıktı dizini oluşturulamadığında (disk dolu/izin
yok) ham bir `OSError`'ın kullanıcıya çirkin bir Python hata izlemesi olarak
sızdığını fark ettim — CLI'nin diğer tüm hatalarda verdiği temiz mesaj
yerine. Yeni bir `RouterError` tipi eklendi, CLI'ye bağlandı, regresyon
testi yazıldı. Toplam **38 test, hepsi geçiyor**.

## 7. Standart dokümantasyon dosyaları eklendi

Kullanıcının her projesinde kullandığı beş dokümanın (özellikler, roadmap,
oturum özeti, hatalar ve sonuçlar, öğrenilenler) TriageChain karşılıkları
oluşturuldu — chameleon projesindeki eşdeğerleri okunup format/ton aynen
takip edildi.

## 8. Faz 4: tespit katmanı (Hayabusa + Sigma)

Toplanan `.evtx` dosyalarını Hayabusa ile tarayıp Sigma kural tabanlı bulgular
üreten `detection/` paketi yazıldı (`triagechain detect`). Router'ın dört
güvenlik kuralı birebir uygulandı; en kritik test, elle değiştirilmiş bir
`manifest.json`'ın vakanın çıktı ağacı dışını göstermesi durumunda
`subprocess`in HİÇ çağrılmadığını doğruluyor.

Bu fazın kendine özgü üç kararı:

- **Hayabusa'nın gerçek CLI sözdizimi bu ortamda doğrulanamadı** (araç kurulu
  değil). Bu yüzden hem çağrı şablonu hem CSV sütun eşlemesi koda değil
  `detection/catalog/hayabusa_args.yaml` veri dosyasına kondu ve ayrıştırma en
  iyi çaba ilkesiyle yazıldı: başlıklar tanınmazsa koşu düşmüyor, 0 bulgu +
  uyarı kaydedilip devam ediliyor.
- **Custody'ye bulgu başına değil, taranan dosya başına tek özet olay**
  yazılıyor; detaylar `detection_manifest.json`'da duruyor, o dosyanın
  SHA-256'sı kapanış olayına işlenerek zincire bağlanıyor.
- Manifesti diske yazan taraf CLI değil koşunun kendisi — hash ancak dosya
  yazıldıktan sonra hesaplanabildiği için.

20 yeni test eklendi, **toplam 58 test, hepsi geçiyor**. Alınan kararların
tamamı [aldigim_kararlar.md](aldigim_kararlar.md)'ye gerekçeleriyle işlendi.

## 9. Faz 5: otomatik raporlama (son çekirdek faz)

`reporting/` paketi yazıldı (`triagechain report`): toplama manifesti,
yönlendirme manifesti, tespit manifesti ve gözetim zincirinin **tam** olay
listesi tek bir `report.json` + tek sayfa `report.html` içinde birleşiyor.
HTML'de büyük ve renkli bir "Zincir Durumu: GEÇERLİ / GEÇERSİZ" göstergesi,
vaka kartı, üç özet tablosu, bulgular tablosu ve olay listesi var; harici
hiçbir CDN/font/script yok — olay yerinde internetsiz açılabiliyor.

Bu fazın kendine özgü kararları:

- **Rapor katmanı deftere YAZMIYOR**, sadece okuyor. Yazsaydı raporun
  içindeki olay listesi ve `verify_chain` sonucu yazıldığı anda eskimiş
  olurdu. İki test bunu kilitliyor (defterin baytları rapordan önce/sonra
  birebir aynı).
- Raporun yanına **`report.json.sha256`** yazılıyor (`<hash>  report.json`
  biçiminde, `sha256sum -c` ile doğrulanabilir) — raporun kendisinin sonradan
  değişip değişmediği zincire bakmadan kontrol edilebiliyor.
- **Kısmi çalıştırma çökmüyor**: `route`/`detect` hiç çalıştırılmamışsa ilgili
  bölüm "henüz çalıştırılmadı" diyor; yalnızca toplama manifesti zorunlu, o
  yoksa `route`/`detect` ile aynı desende temiz mesaj + çıkış kodu 2.
- Yeni `ReportingError` tipi CLI'ye bağlandı; ayrıca tutarlılık için
  `routing_manifest.json` yolu CLI'den `config/loader.py`'ye taşındı
  (`resolve_routing_manifest_path`) ve rapor yolları için `resolve_report_path`
  eklendi.

9 yeni test eklendi, **toplam 67 test, hepsi geçiyor**. Kararların tamamı
[aldigim_kararlar.md](aldigim_kararlar.md)'ye işlendi.

## 10. RECmd'in `--bn` toplu dosyası + metodoloji izlenebilirliği

Roadmap'te "karar bekleniyor" olarak duran iki iş birlikte kapatıldı.

**(1) RECmd artık kutudan çıktığı gibi çalışıyor.** Gerçek testte bulunan
eksik argüman (`RECmd.exe -f <hive> --csv <dizin>` tek başına reddediliyordu)
için üçüncü bir yol seçildi: kullanıcıdan yol istemek ya da kendi minimal
`.reb`'imizi yazmak yerine, topluluk standardı `DFIRBatch.reb`
(`EricZimmerman/RECmd`, MIT) belirli bir sürüme **sabitlenmiş** olarak pakete
gömüldü. `router.recmd_batch_file` config alanı bir *override*; boş
bırakılırsa gömülü dosya kullanılıyor. Dosya bulunamazsa ölümcül değil,
"atlandı" (subprocess hiç çağrılmadan). Sürüm bilerek sabit — "en güncelini
indir" davranışı aynı vakayı farklı zamanlarda farklı kural setiyle
çalıştırır, tekrarlanabilirliği bozardı.

**(2) "Hangi kural seti bu sonucu üretti" sorusu artık defterden
cevaplanabiliyor.** İki araçta iki farklı biçimde:

- **RECmd**: `artifact_processed` olayına kullanılan toplu dosyanın yolu ve
  **içerik SHA-256'sı** yazılıyor (tek dosya → tam ve kesin hash). Kural
  dosyası kavramı olmayan araçlarda (mftecmd/evtxecmd/pecmd) bu alanlar hiç
  yazılmıyor.
- **Hayabusa**: `detection_started` olayına `rules_dir`, `rules_file_count` ve
  bir **yapısal parmak izi** (`rules_fingerprint_sha256`) yazılıyor — klasör
  binlerce dosya içerebildiği için içerikler tek tek hash'lenmiyor, `(göreli
  yol, boyut)` çiftlerinin sıralı listesinden tek bir SHA-256 alınıyor.
  **Sınırı açıkça yazıldı** (kodda, `chain_of_custody.md`'de ve bir testin
  adında): dosya eklenmesi/çıkarılması/boyut değişikliği yakalanır, içeriğin
  aynı boyutta değiştirilmesi YAKALANMAZ. Bu bilinçli bir tradeoff.

İki olayın da **mevcut alanlarına dokunulmadı**, yalnızca yeni anahtarlar
eklendi (geriye dönük uyumluluk). Router'ın dört güvenlik kuralı gevşetilmedi:
toplu dosyanın yolu asla manifest/artefakt verisinden gelmiyor, argv'ye tek
bir liste elemanı olarak giriyor, `shell=True` yok. Gömülü `.reb`'in kurulan
pakete de kopyalanması için `pyproject.toml`'a paket-verisi girdisi eklendi
(aksi halde `recmd_batch/` bir paket olmadığı için dışarıda kalırdı).

10 yeni test eklendi, **toplam 85 test, hepsi geçiyor**. Kararların tamamı
gerekçeleriyle [aldigim_kararlar.md](aldigim_kararlar.md)'ye işlendi.

## 11. VSS `pywin32`'ye (doğrudan WMI COM) taşındı

Kullanıcı, VSS modülünün `subprocess` + `powershell.exe` + metin ayrıştırma
yerine `pywin32` (`win32com.client`) ile doğrudan WMI çağırmasını **açıkça
onayladı** — bu, projenin "bağımlılıktan kaçın" ilkesine bilinçli, kullanıcı
onaylı bir istisna (gerekçe: metin ayrıştırma kırılganlığı tamamen ortadan
kalkıyor ve gölge kopya başına fazladan bir süreç başlatmaya gerek kalmıyor).
Kod deseninin kendisi, yazılmadan ÖNCE kullanıcının makinesinde gerçek bir
Yönetici (UAC) yetkisiyle elle doğrulanmıştı.

`vss_snapshot.py` yeniden yazıldı: `Win32_ShadowCopy.Create()` doğrudan
çağrılıyor, `DeviceObject` ayrı bir `ExecQuery` ile alınıyor, silme WMI
örneğinin kendi `Delete_()` metoduyla yapılıyor (`vssadmin`'e artık hiç
ihtiyaç yok). `parse_create_output`, `_build_create_script` ve `_KV_PATTERN`
silindi. Ham COM istisnaları dışarı sızmıyor, `CollectionError`'a sarılıyor.
`VssSnapshot`'ın public arayüzü (`__init__(volume, timeout)`, `translate()`,
context manager) hiç değişmediği için `collector.py`/`readers.py`'ye
dokunulmadı.

`pyproject.toml`'a `"pywin32>=306; sys_platform == 'win32'"` eklendi —
**platform işaretleyicisi şart**, çünkü CI `ubuntu-latest` üzerinde çalışıyor
ve pywin32'nin Linux wheel'i yok. Aynı sebeple `import win32com.client` modül
seviyesinde `try/except ImportError` ile sarıldı (modül pywin32'siz de import
edilebiliyor, hata ancak gerçekten kullanılınca çıkıyor) ve testler gerçek
pywin32'ye değil, `sys.modules`'a enjekte edilen sahte bir `win32com.client`
modülüne dayanıyor. Bu, pywin32'nin import'unu bloke eden bir CI
simülasyonuyla ayrıca doğrulandı: pywin32 hiç yokken de tüm takım geçiyor.

7 eski test (subprocess/vssadmin tabanlı) 5 yeni WMI testiyle değiştirildi:
başarılı oluşturma + `translate()` + `Delete_()`, `ReturnValue != 0`, ham COM
istisnasının sarılması, pywin32 hiç yokken anlamlı hata, silme hatasının
yutulmayıp sadece loglanması. **Toplam 85 → 83 test, hepsi geçiyor.**

## 12. Profesyonel masaüstü arayüzü (PySide6) yazıldı

Roadmap'te "karar bekleniyor" olarak duran madde (eski `tkinter` arayüzüne
route/detect/report butonları eklensin mi) kapandı: kullanıcı bunun yerine
**gerçek, tek pencereli bir masaüstü uygulaması** istedi. Yeni paket
`src/triagechain/gui_qt/` — `theme.py`, `widgets.py`, `main_window.py`,
`app.py`. `triagechain-gui` konsol komutu artık bunu açıyor; eski
`gui/app.py` (tkinter) dosyasına dokunulmadı, sadece komuta bağlı değil.

Tasarım sistemi sıfırdan kurulmadı: kullanıcının **chameleon** projesindeki
olgun `shared/ui_kit` deseni (renk sabitleri tek dosyada, bileşenler kendi
QSS'lerini bu sabitlerden türetiyor, sol sidebar + sağda değişen içerik)
**uyarlandı** — kod kopyalanmadı, renk kimliği TriageChain'in kendi yeşili.

Palet ölçüldü ve iki yerde düzeltildi:
- Önerilen `BORDER` (`#454C56`) `BG_LAYER2`'ye karşı yalnızca **1.82:1**
  çıktı (UI bileşeni için gereken 3:1'in altında) → **`#6A727E`** (3.24:1).
- Birincil butonun yazısı chameleon'daki gibi beyaz olsaydı yeşil dolgu
  üzerinde **2.54:1** olurdu → `BG_DARKEST` kullanıldı (**7.45:1**).
- `ACCENT_TEXT` ise chameleon'un aksine ayrı bir tona **kaydırılmadı**:
  `#3FB950` zaten `BG_DARKEST`'te 7.45:1, `BG_SURFACE`'te 6.81:1 — küçük
  metin için AA fazlasıyla geçiliyor (chameleon'un mavisi geçmiyordu).

Dashboard gerçek veriyle çalışıyor: dört aksiyon (Toplamayı Başlat /
Yönlendir / Tara / Rapor Üret) her biri ayrı bir `QThread`'de var olan
`run_collection` / `run_router` / `run_detection` / `build_report`
fonksiyonlarını çağırıyor; sonrasında metrik kartları, zincir rozeti ve
Delil Zinciri Defteri tablosu diskteki manifest/defter dosyalarından
**yeniden okunuyor** — arayüzün kendi sayacı yok. Zincir kırıksa kırılma
noktasından sonraki satırlar "Şüpheli". Ham traceback hiçbir yerde
gösterilmiyor. Diğer beş sayfa şimdilik "Bu sayfa yakında geliyor".

5 yeni test, tamamı `QT_QPA_PLATFORM=offscreen` ile (gerçek pencere hiç
açılmadı): vaka yokken kurulum, yer tutucu sayfalar, sahte bir vakada
metrik/tablo değerleri, kasıtlı bozulmuş zincirde "Şüpheli", bozuk config'de
ham traceback gösterilmemesi. **Toplam 83 → 88 test, hepsi geçiyor.**

## 13. Dashboard tasarımı sıfırdan yazıldı, beş sayfanın hepsi işlevsel hale geldi

Kullanıcı, verilen bir referans ekran görüntüsüne (yuvarlak ~14px kartlar,
sidebar ikonları, büyük kalın sayılar, sparkline glow, renkli rozetler)
göre Dashboard'un **baştan** yazılmasını istedi — önceki oturumda bilinçli
olarak seçilen `RADIUS=5` ("AI-dashboard hissi" vermesin diye) bu açık
talimatla değiştirildi. `ui-ux-pro-max` skill'i tipografi/UX kontrolü için
kullanıldı. Ardından beş yer tutucu sayfa (Vakalar, Delil Zinciri,
Raporlar, Bulgular, Toplanan Dosyalar) tek tek işlevsel hale getirildi —
her biri diskteki gerçek manifest/defter dosyalarından okuyor, arayüzün
kendi hesabı/sayacı yok. Sparkline + delta metinleri de gerçek veriden
türetildi, hiçbir sayı uydurulmadı (bkz. `aldigim_kararlar.md`).

## 14. Gömülü fontlar ve standalone `.exe` paketleme

Font, gerçek çalıştırmada (test ortamındaki offscreen render'dan farklı
olarak) sistemde kurulu olmayabileceği için çok farklı göründü. Çözüm:
Inter + JetBrains Mono TTF dosyaları OFL lisansıyla `gui_qt/assets/fonts/`
altına gömüldü (kaynak/sürüm/SHA-256 `PROVENANCE.md`'de), `QFontDatabase.
addApplicationFont()` ile uygulama başında yükleniyor, `pyproject.toml`
paket verisi olarak güncellendi. Bu süreçte iki Qt hatası bulundu ve
düzeltildi (özel widget'lı tablo hücrelerinde satır/sütun boyutlandırma —
bkz. `hatalar_ve_sonuclar.md`). Ardından kullanıcı "gerçek bir app, .py
değil .exe" istedi: `triagechain_gui.spec` (PyInstaller `--onefile`) ile
`TriageChainKonsolu.exe` üretildi ve çalıştırılıp doğrulandı.

## 15. YARA entegrasyonu: statik imza taraması

Kullanıcı "gerçek bir YARA'yı indirip entegre et" dedi. Gerçek `yara64.exe`
4.5.5 indirilip gerçek bir `.yar` kuralı + gerçek bir hedef dosyaya karşı
çalıştırılarak argüman şablonu ve stdout satır deseni doğrulandı
(`detection/catalog/yara_args.yaml`). `detection/yara_runner.py`,
router/detection'ın aynı yedi güvenlik kuralını izliyor; tek fark sonucun
stdout'a yazılması. Kural dosyası bilerek **dağıtılmadı** (çoğu açık kaynak
seti kısıtlayıcı lisanslı). Sigma/Hayabusa ile YARA'nın AYNI dosyayı
işaretlediği durumlar `detection/correlation.py::correlate_findings` ile
bulunup rapora/arayüze işlendi. CLI'ye `yara-scan`, GUI'ye "YARA Tara"
butonu + Bulgular sayfasına eşleşme tablosu eklendi. 19 yeni test.

## 16. Chainsaw entegrasyonu, dual-tab raporlar, Yönetici Raporu risk motoru

Aynı istekte üç büyük parça birden tamamlandı:

- **Chainsaw** — Hayabusa'dan bağımsız, gerçek Chainsaw v2.16.5 ikilisini
  çağıran ikinci bir Sigma motoru. Kasıtlı olarak Hayabusa'nın AYNI
  `rules_dir`'ini paylaşıyor (kendine ait kural klasörü yok) — amaç iki
  bağımsız motorun aynı kural setiyle aynı sonuca varıp varmadığını görmek.
  Gerçek EVTX-ATTACK-SAMPLES + gerçek SigmaHQ kurallarıyla doğrulandı (8
  gerçek tespit). `correlate_sigma_engines()` motor ittifakını buluyor.
- **Raporlar iki sekmeye ayrıldı**: "Yönetici Raporu" (teknik olmayan,
  deterministik risk seviyesi — `reporting/executive.py`) ve "Uzman
  Raporu" (teknik detayın tamamı, saf CSS sekme geçişi, JS yok).
- **MITRE ATT&CK etiketleri** Sigma kuralının kendi metadatasından
  yansıtıldı (yeni veri kaynağı/ağ çağrısı yok); CVE entegrasyonu
  araştırılıp bilerek eklenmedi (gerekçe `aldigim_kararlar.md`'de).

Yönetici Raporu'nun risk kuralı hem Chainsaw bulgularını hem motor
ittifakını hesaba katacak şekilde genişletildi; GUI'ye "Chainsaw Tara"
butonu + Bulgular sayfasına Chainsaw tablosu/ittifak vurgusu eklendi.
26 yeni test.

## 17. Roadmap'in kalan çekirdek maddeleri: VSS zaman aşımı, custody çoklu-yazıcı, çoklu disk

Kullanıcı "roadmapteki geliştirmeleri sırayla, onay beklemeden, kendi
kararlarını alarak yap" dedi. Üç bilinen sınırlama gerçek testlerle
kapatıldı:

- **VSS gerçek zaman aşımı**: oluşturma/silme çağrıları ayrı bir daemon
  thread'de `join(timeout)` ile bekleniyor; gerçek bir askıda-kalma
  senaryosu (`time.sleep` ile yavaşlatılmış sahte WMI çağrısı) 2 testle
  doğrulandı.
- **Custody defterine gerçek çoklu-yazıcı desteği**: stdlib dosya kilidi
  (`msvcrt`/`fcntl`, yeni bağımlılık yok) ile "oku → ekle" atomik hale
  getirildi; 8 eşzamanlı yazıcıyla gerçek bir çatallanma testi eklendi.
- **Çoklu disk/birim desteği**: `collection.additional_volumes` ile ek
  disklerin `$MFT`'si de toplanabiliyor (sadece `$MFT`, bilinçli bir kapsam
  sınırı).

Tüm `docs/` dosyaları (mimari, chain-of-custody, özellikler, öğrenilenler,
konfigürasyon referansı, roadmap) bu geliştirmeleri yansıtacak şekilde
güncellendi; her karar gerekçesiyle `aldigim_kararlar.md`'ye işlendi.

## 18. capa entegrasyonu: yeni bir "şüpheli dosya" toplama kavramı

Roadmap'in "capa — PE dosyaları üzerinde otomatik davranış/yetenek
analizi" maddesi için gerçek capa 9.4.0 (Mandiant/FLARE) indirilip gerçek
bir PE dosyasına (notepad.exe) karşı çalıştırılarak `-j` JSON çıktısı
doğrulandı. Bu sırada bir mimari boşluk fark edildi: katalogdaki hiçbir
mevcut hedef (MFT, registry, event log, prefetch) gerçek bir PE dosyası
toplamıyordu — capa'nın girdisi tam olarak budur. Çözüm: `collection.
suspicious_binaries` — analistin elle gösterdiği şüpheli `.exe`/`.dll`
dosyalarının mutlak yolları, katalogdaki diğer hedefler gibi sabit bir
konum DEĞİL, vakaya özgü bir liste.

Veri modeli için Finding/DetectionManifest yerine **YARA'nın `YaraMatch`/
`YaraManifest` şeması yeniden kullanıldı** — capa da (YARA gibi) tek bir
dosyaya karşı çalışıp adlandırılmış kural eşleşmeleri üretiyor. En önemli
karar: capa sonucu **Yönetici Raporu'nun risk hesabına BİLEREK KATILMIYOR**
ve YARA/Sigma ile bir korelasyon üretmiyor — capa "yetenek" tespit ediyor
("bu dosya mutex açabilir" gibi), kötü amaçlı davranış değil; gerçek,
zararsız bir notepad.exe'de bile 35 capa kuralı eşleşti. Bunu YARA/Sigma
eşleşmesiyle aynı ağırlıkta bir risk sinyali saymak, Yönetici Raporu'nu
anlamsızlaştırırdı.

CLI'ye `capa-scan` komutu, GUI'ye "capa Tara" butonu ve Bulgular sayfasına
capa yetenek tablosu eklendi; tüm `docs/` dosyaları bu geliştirmeyi
yansıtacak şekilde güncellendi. 18 yeni test (toplam 175). Kararların
tamamı `aldigim_kararlar.md`'ye işlendi.

## Şu an bekleyen

- Çekirdek fazlar, masaüstü arayüzünün TÜM altı sayfası, YARA, Chainsaw,
  capa, dual-tab raporlama, çoklu disk, custody çoklu-yazıcı, VSS zaman
  aşımı, gömülü fontlar ve standalone `.exe` paketleme bitti.
- Roadmap'te sırada: **Plaso/log2timeline** (süper zaman çizelgesi) — bkz.
  [roadmap.md](roadmap.md).
- Kapsam dışı bırakılanlar (kullanıcıdan ek onay gerektirir): Volatility 3
  (bellek analizi), Timesketch/ELK (web tabanlı çok kullanıcılı
  görselleştirme), RFC 3161 zaman damgası (TSA) entegrasyonu.
- Roadmap tükendiğinde sıradaki adım, mevcut güvenlik-testi skill'leriyle
  uçtan uca bir güvenlik incelemesi yapmak.
