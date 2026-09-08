# Yapılacaklar / fikirler

## Yapıldı

- **Faz 1 mimarisi tasarlandı ve onaylandı** — bir mimar ajanına (Software
  Architect) toplama katmanı + chain-of-custody için tam bir tasarım
  hazırlatıldı: `src/` paket yerleşimi, hash-chaining şeması
  (`entry_hash = sha256(prev_hash + kanonik_json(olay))`, vaka bazlı genesis
  hash), YAML tabanlı artefakt kataloğu, config şeması. Tasarım sırasında iki
  önemli karar netleşti: (1) kilitli Windows dosyaları (`$MFT`, registry
  kovanları) için VSS kullanılacak — `pywin32`/COM değil, `vssadmin`
  subprocess çağrısıyla; (2) **KAPE'nin kendisi açık kaynak değil** (Kroll
  lisanslı, kapalı kaynak) — bunun yerine KAPE'nin açık kaynaklı hedef
  tanımları (`EricZimmerman/KapeFiles`) sadece *veri* olarak referans alınıp
  kendi kataloğumuz yazıldı, KAPE.exe'ye hiçbir bağımlılık yok.
- **Faz 1 implementasyonu tamamlandı**: `collection/` (VSS, hash, katalog
  tabanlı seçim, hedef toplama), `custody/` (hash-zincirli JSONL defter,
  `verify_chain`), `config/` (pydantic şema, YAML yükleyici), `cli/`
  (`collect`, `verify-custody`). Sadece 2 bağımlılık: `pydantic`, `PyYAML`.
  24 test yazıldı, hepsi geçti. `git init` yapıldı (commit/push yok).
- **Basit çalıştırma arayüzü eklendi** (`triagechain-gui`) — sadece stdlib
  `tkinter`, ek bağımlılık yok. Vaka bilgisi, hedef seçimi (kataloğdan
  dinamik), ayarlar, config yükle/kaydet, toplama (arka plan thread'i) ve
  zincir doğrulama. Görsel tasarım bilinçli olarak sade — profesyonel
  tasarım ayrı bir aşamaya bırakıldı.
- **Faz 2: format dönüştürme / router katmanı tamamlandı** — toplanan her
  dosya tipine göre MFTECmd/RECmd/EvtxECmd/PECmd'ye yönlendiriliyor
  (`router/catalog/tool_mapping.yaml`, veri dosyası). Güvenlik: `shell=True`
  hiçbir yerde yok (argüman listesi), araç yolları config'de mutlak olmak
  zorunda, girdi yolu vakanın kendi `output_dir/artifacts` ağacı dışındaysa
  hiçbir şey çalıştırılmıyor (tampered `manifest.json`'a karşı savunma), her
  çağrının zaman aşımı var. Yönlendirme olayları (`artifact_processed`,
  `processing_skipped`, `processing_error`) aynı custody zincirine ekleniyor.
  Gerçek EZ Tools ikilisi olmadan, `subprocess.run` mock'lanarak test
  edildi (13 yeni test, toplam 37).
- **İnceleme sırasında bulunan bir eksik düzeltildi**: çıktı dizini
  oluşturulamazsa (disk dolu/izin yok) ham `OSError` kullanıcıya çirkin bir
  Python hata izlemesi olarak sızıyordu. Yeni bir `RouterError` tipi eklenip
  CLI'nin temiz hata mesajı verme deseniyle (`ConfigError` vb. gibi)
  bütünleştirildi, regresyon testi eklendi (toplam 38 test). Detaylar:
  [hatalar_ve_sonuclar.md](hatalar_ve_sonuclar.md).

- **Faz 4: tespit katmanı (Hayabusa + Sigma) tamamlandı** — toplanan `.evtx`
  dosyaları Hayabusa'ya verilip Sigma kural tabanlı bulgulara çevriliyor
  (`triagechain detect`). Çağrı sözdizimi ve CSV sütun eşlemesi kod değil veri
  (`detection/catalog/hayabusa_args.yaml`). Router'ın dört güvenlik kuralı
  birebir uygulandı. Çıktı ayrıştırma en iyi çaba: başlıklar tanınmazsa koşu
  düşmüyor, uyarı + ham dosya yolu kaydedilip devam ediliyor. Custody'ye bulgu
  başına değil, taranan dosya başına tek özet olay yazılıyor; detaylar
  `detection_manifest.json`'da, o dosyanın SHA-256'sı ise `detection_completed`
  olayında. Yeni `DetectionError` tipi CLI'ye bağlandı. 20 yeni test (toplam
  58), hepsi `subprocess.run` mock'lanarak — bu makinede Hayabusa kurulu değil.

- **Faz 5: otomatik raporlama tamamlandı** — `triagechain report`, vakanın
  bütün çıktılarını (toplama manifesti, yönlendirme manifesti, tespit
  manifesti, gözetim zincirinin TAM olay listesi ve o andaki `verify_chain`
  sonucu) tek bir `report.json` + tek sayfa `report.html` içinde birleştiriyor.
  HTML tamamen offline: harici hiçbir CDN/font/script/stil yok. Raporun
  yanına, raporun kendisinin sonradan değişip değişmediğini gösteren
  `report.json.sha256` yazılıyor. Yönlendirme/tespit hiç çalıştırılmadıysa
  ilgili bölüm "henüz çalıştırılmadı" diyor, çökmüyor. Bu katman deftere
  YAZMIYOR (salt-okunur gözlemci — bkz.
  [aldigim_kararlar.md](aldigim_kararlar.md)). Yeni `ReportingError` tipi
  CLI'ye bağlandı, `routing_manifest.json` yolu da tutarlılık için
  `config/loader.py`'ye taşındı. 9 yeni test (toplam 67).

- **RECmd'in `--bn` toplu dosyası çözüldü: standart `DFIRBatch.reb` pakete
  gömüldü** — gerçek testte bulunan eksik argüman (`RECmd.exe -f <hive> --csv
  <dizin>` tek başına reddediliyordu) artık kapandı. `EricZimmerman/RECmd`
  deposundaki MIT lisanslı `DFIRBatch.reb`'in belirli bir sürüme
  **sabitlenmiş** kopyası `router/catalog/recmd_batch/` altına gömüldü
  (kaynak/sürüm/commit/SHA-256 `PROVENANCE.md`'de). `tool_mapping.yaml`'daki
  RECmd rotalarına `--bn {batch_file}` eklendi; `router.recmd_batch_file`
  config alanı ile kullanıcı kendi dosyasını gösterebiliyor, boş bırakırsa
  gömülü dosya kullanılıyor. Dosya bulunamazsa ölümcül değil, "atlandı".
- **Metodoloji izlenebilirliği (reproducibility) custody'ye işlendi** — "bu
  bulguyu hangi kural seti üretti" sorusu artık defterden cevaplanabiliyor:
  `artifact_processed` olayına (yalnızca RECmd rotasında) kullanılan toplu
  dosyanın yolu + **SHA-256'sı**, `detection_started` olayına ise Sigma kural
  klasörünün **yapısal parmak izi** (`rules_dir`, `rules_file_count`,
  `rules_fingerprint_sha256`) yazılıyor. Parmak izi dosya içeriklerinden değil
  `(göreli yol, boyut)` listesinden hesaplanıyor — bilinçli bir tradeoff, sınırı
  [chain_of_custody.md](chain_of_custody.md)'de açıkça yazılı. 10 yeni test
  (toplam 85).
- **VSS artık `pywin32` (WMI COM) ile — `powershell.exe` + metin ayrıştırma
  kaldırıldı** — kullanıcının açık onayıyla alınan, bilinçli bir bağımlılık
  istisnası (`pyproject.toml`'da `sys_platform == 'win32'` işaretleyicisiyle,
  CI Linux'ta çalıştığı için şart). `Win32_ShadowCopy.Create()` doğrudan
  çağrılıyor, silme WMI örneğinin kendi `Delete_()` metoduyla yapılıyor;
  `parse_create_output`/`_build_create_script`/`_KV_PATTERN` silindi.
  `VssSnapshot`'ın public arayüzü (`__init__(volume, timeout)`, `translate()`,
  context manager) aynı kaldı, collector'a dokunulmadı. Testler gerçek
  pywin32'ye değil, `sys.modules`'a enjekte edilen sahte bir `win32com.client`
  modülüne dayanıyor — 7 eski test yerine 5 yeni test (toplam 83).

- **Profesyonel masaüstü arayüzü (`PySide6`) tamamlandı** — `triagechain-gui`
  artık tek pencerede, solda sabit sidebar + sağda `QStackedWidget` olan
  gerçek bir uygulama açıyor (`src/triagechain/gui_qt/`). Dört CLI komutu da
  (collect / route / detect / report) buradan, her biri ayrı bir `QThread`'de
  çalışıyor — arayüz donmuyor, çalışan buton kapanıyor, belirsiz ilerleme
  çubuğu dönüyor. Dashboard'daki üç metrik kartı ve Delil Zinciri Defteri
  tablosu **gerçek veriyi diskten** okuyor (`manifest.json`,
  `detection_manifest.json`, `custody.jsonl` + `verify_chain`); zincir
  kırıksa kırılma noktasından sonraki satırlar "Şüpheli" gösteriliyor. Ham
  Python traceback'i hiçbir yerde gösterilmiyor. Tasarım sistemi kullanıcının
  chameleon projesindeki `shared/ui_kit` deseninden **uyarlandı** (kopya
  değil), renkler TriageChain'in kendi yeşil kimliği; kontrast hesabı
  önerilen `BORDER` değerini ve birincil buton yazı rengini değiştirdi (bkz.
  [aldigim_kararlar.md](aldigim_kararlar.md)). Eski `tkinter` arayüzü
  (`gui/app.py`) silinmedi, sadece komuta bağlı değil. Yeni bağımlılık:
  `PySide6>=6.7` (platform işaretleyicisi gerekmiyor). 5 yeni test, tamamı
  `QT_QPA_PLATFORM=offscreen` ile (toplam 88).

- **İçe aktarma modu (`collection.source_root`) eklendi** — TriageChain
  artık SADECE canlı bir Windows sistemine karşı değil, BAŞKA bir araçla
  (örn. KAPE) önceden toplanmış bir artefakt ağacına karşı da
  çalıştırılabiliyor. Ayarlandığında katalog VSS hiç açmadan, tüm hedefleri
  bu kök altına yeniden köklendiriyor. Gerçek bir üniversite KAPE
  ödevi verisiyle uçtan uca doğrulandı (384/384 dosya, 0 hata; ardından
  gerçek MFTECmd/RECmd/EvtxECmd/PECmd ile `route`, 0 hata). Bu test
  sırasında ayrıca Windows'un 260 karakter `MAX_PATH` sınırını aşan (uzun
  olay günlüğü kanal adları) gerçek, önceden fark edilmemiş bir hata
  bulunup düzeltildi (`collection/winpath.py::to_long_path`, beş dosyaya
  uygulandı). Detaylar `aldigim_kararlar.md`'de. 6 yeni test (toplam 196).

## Sırada

1. ~~Hayabusa CSV başlıkları doğrulanamadı~~ **tamamlandı** — kullanıcının
   sağladığı gerçek (saldırıya uğramış) laboratuvar verisiyle 5.124 gerçek
   bulgu üretildi, CSV başlıkları varsayılanla birebir eşleşti, projenin
   kendi ayrıştırıcısı doğrulandı (bkz.
   [hatalar_ve_sonuclar.md](hatalar_ve_sonuclar.md)).
2. ~~Gerçek EZ Tools ile canlı test yapılmadı~~ **kısmen tamamlandı** —
   EvtxECmd ve MFTECmd gerçek verilerle doğrulandı, sözdizimi doğru çıktı.
   RECmd'de eksik bir varsayım bulundu (`--bn <toplu dosya>` gerekiyormuş) ve
   bununla bağlantılı bir toplama eksikliği de (registry kovanlarının
   `.LOG1`/`.LOG2` transaction log dosyaları toplanmıyordu) düzeltildi — bkz.
   [hatalar_ve_sonuclar.md](hatalar_ve_sonuclar.md). `--bn` toplu dosyası
   sorusu da **çözüldü** (yukarıdaki "Yapıldı" maddesine bakın): standart
   `DFIRBatch.reb` sabitlenmiş bir sürümle pakete gömüldü. **Kalan iş:**
   gömülü toplu dosyayla gerçek `RECmd.exe`'ye karşı canlı bir doğrulama —
   `--bn` bayrağının kendisi gerçek kovana karşı zaten test edilmişti (başka
   bir `.reb` ile), ama bu ÖZEL dosyayla uçtan uca koşu henüz yapılmadı.
3. ~~VSS yolu gerçek bir Windows makinesinde test edilmedi~~ **tamamlandı** —
   gerçek bir Yönetici (UAC) oturumunda uçtan uca doğrulandı, bu sırada
   `vssadmin create shadow`'un artık çalışmadığı bulunup WMI tabanlı bir
   çözümle düzeltildi (bkz. [hatalar_ve_sonuclar.md](hatalar_ve_sonuclar.md)).
   O günkü çözüm WMI'yi `powershell.exe` üzerinden çağırıyordu; sonradan
   `pywin32` ile doğrudan çağrıya taşındı (yukarıdaki "Yapıldı" maddesi).
   **Kalan iş:** `pywin32` sürümüyle, gerçek bir UAC oturumunda uçtan uca bir
   `triagechain collect` koşusu — WMI kod deseninin kendisi gerçek makinede
   elle doğrulandı, ama TriageChain içinden çalıştırılmış hâli henüz değil.
4. ~~**Karar bekleniyor**: GUI'ye "Ayrıştır / Route", "Tara / Detect" ve
   "Rapor / Report" butonları eklensin mi?~~ **kapandı** — eski `tkinter`
   arayüzüne buton eklemek yerine, PySide6 ile yeni bir masaüstü uygulaması
   yazıldı ve dört komut da oraya bağlandı (yukarıdaki "Yapıldı" maddesi).
   ~~**Kalan iş:** Vakalar / Delil Zinciri / Raporlar / Bulgular / Toplanan
   Dosyalar sayfaları şu an yalnızca "Bu sayfa yakında geliyor" yer tutucusu~~
   **tamamlandı** — beş sayfanın hepsi gerçek veriyle çalışıyor: Toplanan
   Dosyalar (manifest.artifacts tam liste), Delil Zinciri (custody defterinin
   50 satır sınırı olmayan tam hali), Bulgular (tespit manifestindeki tüm
   bulgular), Raporlar (en son üretilmiş `report.json`'un özeti — tek rapor,
   sürüm geçmişi yok), Vakalar (`collection.output_dir` altında diskte
   bulunan HER vaka klasörünün taranmasıyla — bkz. `list_case_summaries()`).
   16 yeni test (toplam 99). Ayrıca kullanıcının onayladığı referans
   tasarıma göre Dashboard'un görsel dili de baştan yazıldı (radius/padding/
   font ölçütleri, sidebar ikonları — bkz. `aldigim_kararlar.md`).
   ~~**Kalan iş:** kullanıcı gerçek masaüstünde çalıştırınca `Inter`/
   `JetBrains Mono` fontlarının kurulu olmadığı, Qt'nin sessizce yedek fonta
   düştüğü görüldü~~ **ÇÖZÜLDÜ** — fontlar `gui_qt/assets/fonts/`'a gömüldü
   (OFL lisanslı, resmi kaynaklardan indirildi, bkz. oradaki
   `PROVENANCE.md`), `app.py` başlangıçta yüklüyor (bkz.
   `aldigim_kararlar.md` → "Dashboard'un görsel yeniden tasarımı"). Bu turda
   ayrıca iki gerçek Qt tablo hatası bulunup düzeltildi (satır/sütun
   boyutlandırma özel widget'ların `sizeHint()`'ini kaçırıyordu — bkz.
   `hatalar_ve_sonuclar.md`); gerçek ekranda henüz elle doğrulanmadı.
5. PECmd (prefetch aracı) gerçek bir dosyaya karşı henüz denenmedi —
   EvtxECmd/MFTECmd'nin aksine bu turda test edilmedi.

- **YARA entegrasyonu tamamlandı** — ikinci bir tespit katmanı olarak
  eklendi (`detection/yara_runner.py`), Hayabusa ile BİREBİR aynı mimari
  desende (BYO tool: `detection.yara_path`/`yara_rules_file` config,
  subprocess güvenlik kuralları birebir aynı). Gerçek `yara64.exe 4.5.5`
  (resmi VirusTotal/yara GitHub sürümü) indirilip gerçek bir eşleşme/
  eşleşmeme senaryosuna karşı elle doğrulandı (bkz. `aldigim_kararlar.md`),
  çıktı formatı buna göre yazıldı. `detection/correlation.py` iki motorun
  (Sigma/Hayabusa ve YARA) aynı dosyayı işaretlediği durumları kümе
  kesişimiyle buluyor. CLI'ye `yara-scan` komutu, GUI'ye "YARA Tara" butonu
  ve Bulgular sayfasına YARA eşleşme tablosu + korelasyon vurgusu eklendi.
  Rapor katmanına (`Report.yara`, `Report.correlated_artifacts`) ve HTML
  rapora (YARA özeti + korelasyon bölümü) da işlendi. Kural dosyası
  BİLEREK vendor edilmedi (Yara-Rules/rules GPLv2 — lisans riski, ayrıca
  proje zaten "araç dağıtılmaz" ilkesini benimsiyor); kullanıcı kendi
  `.yar` dosyasını gösteriyor. 19 yeni test (toplam 129).
- **MITRE ATT&CK etiketleri eklendi, CVE entegrasyonu bilerek eklenmedi**
  — Sigma kurallarının kendi metadatasındaki ATT&CK etiketleri (Hayabusa
  `MitreTactics` sütunu varsa) `Finding.mitre_tags`'e yansıtılıyor; CVE
  için gerekçesi `aldigim_kararlar.md`'de.
- **Raporlar sayfası iki sekmeye ayrıldı**: "Yönetici Raporu" (teknik
  olmayan, deterministik risk seviyesi + düz metin özet —
  `reporting/executive.py`) ve "Uzman Raporu" (eskiden beri var olan
  teknik detay). Hem GUI'de hem offline HTML raporda (saf CSS sekme
  geçişi, JS yok) mevcut.
- **Chainsaw** — Sigma tabanlı, Hayabusa'dan BAĞIMSIZ ikinci bir tespit
  motoru (gerçek Chainsaw v2.16.5, WithSecure) eklendi. Hayabusa ile AYNI
  `detection.rules_dir`'i paylaşıyor (yeni `chainsaw_rules_dir` YOK) —
  amaç iki bağımsız motorun aynı kural setiyle aynı sonuca varıp
  varmadığını görmek (`detection/correlation.py::correlate_sigma_engines`).
  CLI'ye `chainsaw-scan` komutu, GUI'ye "Chainsaw Tara" butonu ve Bulgular
  sayfasına Chainsaw bulgu tablosu + motor ittifakı vurgusu eklendi. Rapor
  katmanına (`Report.chainsaw`, `Report.engine_agreements`) ve HTML rapora
  (Chainsaw özeti + "Motor ittifakı" bölümü) işlendi; Yönetici Raporu'nun
  risk kuralı da artık Chainsaw bulgularını ve motor ittifakını sayıyor
  (`reporting/executive.py`). Gerekçe ve detaylar `aldigim_kararlar.md`'de.
  26 yeni test (toplam 155).
- **capa** — PE dosyaları üzerinde otomatik davranış/yetenek analizi
  (gerçek capa 9.4.0, Mandiant/FLARE) eklendi. Bunun için yeni bir toplama
  kavramı gerekti: `collection.suspicious_binaries` — analistin elle
  gösterdiği şüpheli `.exe`/`.dll` dosyaları (katalogdaki diğer hedefler
  gibi sabit bir konum değil). capa SADECE bu dosyaları tarar; veri modeli
  YARA ile AYNI `YaraMatch`/`YaraManifest` şemasını paylaşıyor (capa da tek
  bir dosyaya karşı çalışıp adlandırılmış kural eşleşmeleri üretiyor).
  **Bilinçli olarak** Yönetici Raporu'nun risk hesabına KATILMIYOR: capa
  "yetenek" tespit eder, kötü amaçlı davranış değil — gerçek, zararsız bir
  `.exe`'de bile onlarca capa kuralı eşleşir. CLI'ye `capa-scan` komutu,
  GUI'ye "capa Tara" butonu ve Bulgular sayfasına capa yetenek tablosu
  eklendi. Gerekçe ve detaylar `aldigim_kararlar.md`'de. 18 yeni test
  (toplam 175).
- **Birleşik zaman çizelgesi** — Plaso'nun kurulamamasının (aşağıdaki
  "Daha sonra" bölümüne bkz.) YERİNE, TriageChain'in ZATEN ürettiği
  MFTECmd/RECmd/EvtxECmd/PECmd CSV çıktılarını okuyup TEK bir kronolojik
  listede birleştiren yeni bir katman (`reporting/timeline.py`) eklendi —
  HİÇBİR yeni dış araç/bağımlılık gerektirmiyor. Dört gerçek EZ Tools
  ikilisi (2026.5.0, net9) gerçek örnek verilere ($MFT, NTUSER.DAT/SAM
  registry kovanları, UACME_59_Sysmon.evtx, bir NOTEPAD.EXE prefetch
  dosyası) karşı çalıştırılıp CSV şemaları doğrulandı. `triagechain
  report`'a (`Report.timeline`, HTML "Zaman çizelgesi" bölümü) ve GUI'nin
  Raporlar sayfasına işlendi. **Not:** Plaso'nun ~600 ayrıştırıcısının
  (tarayıcı geçmişi, disk imajı biçimleri vb.) tam kapsamının YERİNE
  GEÇMEZ — sadece TriageChain'in zaten topladığı/ayrıştırdığı dört
  kaynağı birleştirir. 8 yeni test (toplam 183).

## Daha sonra, öncelik sırası netleşmedi

Kullanıcının orijinal proje planındaki sıralamayla:

- **Plaso / log2timeline (kendisi)** — tüm parser çıktılarını birleştiren
  ~600 ayrıştırıcılı GERÇEK süper zaman çizelgesi aracı. **BİLİNÇLİ OLARAK
  ERTELENDİ** (kullanıcı onayıyla, "ileride yapılacak"): `pip install
  plaso` bu geliştirme ortamında GERÇEKTEN denendi ve başarısız oldu —
  Plaso'nun native bağımlılıkları (libewf/libfsapfs/libfvde gibi libyal
  kütüphaneleri) Windows'ta bir C++ derleyicisi (Visual C++ Build Tools)
  gerektiriyor, bu makinede yok. Önceki dört entegrasyonun (Chainsaw/YARA/
  capa) hepsinde ısrarla yapılan "gerçek ikiliye karşı doğrula" adımı
  burada atlanmak zorunda kalacaktı; bu riski kullanıcıya açıkça sunup
  onun kararıyla ertelendi. Yukarıdaki "Birleşik zaman çizelgesi"
  TriageChain'in KENDİ dört aracının kapsamını karşılıyor ama Plaso'nun
  genişliğinin (disk imajı biçimleri, tarayıcı/uygulama artefaktları vb.)
  yerini TUTMUYOR. Kullanıcı gerçek bir kurulumla (VC++ Build Tools, WSL
  ya da Docker) test edebildiğinde ayrı bir oturumda ele alınmalı — bkz.
  `aldigim_kararlar.md`.
- **Volatility 3** — bellek (RAM) imajı analizi (şu an kapsam dışı).
- **Timesketch / ELK** — web tabanlı, çok kullanıcılı, interaktif zaman
  çizelgesi görselleştirme.
- **RFC 3161 zaman damgası (TSA) entegrasyonu** — "bu hash bu zamanda vardı"
  kanıtını üçüncü taraf onaylı hale getirmek. `CustodyEvent.payload`'daki
  `tsa_token` alanı bunun için zaten ayrılmış durumda (şu an her zaman
  `null`), şema değişikliği gerekmeyecek.
- ~~**Çoklu disk/birim desteği**~~ **tamamlandı** — `collection.
  additional_volumes` ile ek disklerin `$MFT`'si de toplanıyor (sadece
  $MFT; registry/event log/prefetch sistem diskine özgü kaldı — bkz.
  `aldigim_kararlar.md`).
- ~~**VSS için gerçek zaman aşımı**~~ **tamamlandı** — `VssSnapshot`'ın
  oluşturma/silme çağrıları artık ayrı bir daemon thread'de çalışıp
  `join(timeout)` ile bekleniyor; gerçekten askıda kalma senaryosu 2 yeni
  testle doğrulandı (bkz. `aldigim_kararlar.md`).
- ~~**Custody defterinin gerçek çoklu-yazıcı desteği**~~ **tamamlandı** —
  `storage.locked()` (stdlib `msvcrt`/`fcntl`, yeni bağımlılık yok) ile
  `append_event()` artık atomik; 8 eşzamanlı yazıcıyla gerçek bir
  çatallanma testi eklendi (bkz. `aldigim_kararlar.md`).
