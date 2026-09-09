# TriageChain — Özellikler

TriageChain, KAPE ve Eric Zimmerman Tools gibi açık kaynak DFIR araçlarını
tek bir otomatik pipeline'da birleştiren, chain-of-custody (delil zinciri)
standartlarına uygun bir adli bilişim triaj sistemidir. Bu doküman, şu ana
kadar (Faz 1 + Faz 2 + Faz 4 + Faz 5 — yani çekirdek fazların tamamı, ardından
roadmap'teki YARA/Chainsaw/çoklu disk/çoklu yazıcı/gömülü font/exe
geliştirmeleri) tamamlanan özellikleri anlatır.

## 1. Toplama katmanı (collection)

- **Katalog tabanlı hedef seçimi**: MFT, registry kovanları (SYSTEM, SAM,
  SECURITY, SOFTWARE, kullanıcı başına NTUSER.DAT/UsrClass.dat), Windows olay
  günlükleri (`.evtx`) ve prefetch dosyaları — hepsi kod içine gömülü değil,
  değiştirilebilir bir YAML katalogunda (`collection/catalog/default_targets.yaml`)
  tanımlı.
- **Kilitli dosyalara VSS ile erişim**: `$MFT` ve registry kovanları Windows
  çalışırken kilitlidir; bunlar için `pywin32` ile WMI'nin
  `Win32_ShadowCopy.Create()` metodu doğrudan çağrılarak geçici bir Volume
  Shadow Copy açılıp oradan okunuyor (KAPE'nin de kullandığı yöntem), işlem
  bitince gölge kopya (WMI örneğinin kendi `Delete_()` metoduyla) siliniyor.
  Oluşturma VE silme çağrılarının **gerçek** bir zaman aşımı var (ayrı bir
  daemon thread + `join(timeout)`); askıda kalma gerçek bir testle doğrulandı
  (bkz. `aldigim_kararlar.md`).
- **Çoklu disk/birim desteği**: `collection.additional_volumes` ile ek
  disklerin (`D:`, `E:` vb.) de `$MFT`'si toplanabiliyor — sadece `$MFT`
  (registry/olay günlüğü/prefetch sistem diskine özgü kalıyor, bilinçli bir
  kapsam sınırı). Kullanılamayan bir birim ölümcül sayılmıyor.
- **Akış halinde hash + kopyalama**: Her dosya okunurken aynı anda SHA-256
  (veya seçilen algoritma) hesaplanıyor; yazılan dosya bir daha hash'lenip
  akış sırasında hesaplanan değerle karşılaştırılıyor — kısmi/bozuk bir
  kopya asla fark edilmeden geçmiyor (`IntegrityError`, ölümcül).
- **Kısmi başarısızlığa dayanıklı**: Tek bir artefakt alınamazsa (dosya yok,
  erişim reddedildi) bu ölümcül sayılmıyor, kaydedilip bir sonraki hedefe
  geçiliyor — gerçek dünyada her hostta her artefakt bulunmaz.

## 2. Chain-of-custody (delil zinciri)

- Her önemli olay (vaka açıldı/kapandı, dosya toplandı, toplama hatası,
  ayrıştırma yapıldı/atlandı/hata verdi, YARA/Chainsaw taraması yapıldı/
  atlandı/hata verdi) zaman damgalı olarak, **bir önceki kaydın hash'ine
  zincirlenmiş** (hash-chaining) bir deftere yazılıyor.
- Defter **append-only** (JSON Lines) — hiçbir kayıt yerinde değiştirilmiyor.
- **Gerçek çoklu-yazıcı desteği**: `custody/storage.py`'deki `locked()`
  context manager'ı stdlib dosya kilidiyle (Windows `msvcrt`, POSIX
  `fcntl` — yeni bağımlılık yok) "son hash'i oku → kaydı ekle" işlemini
  süreçler arası atomik hale getiriyor; 8 eşzamanlı yazıcıyla gerçek bir
  çatallanma senaryosu testle doğrulandı.
- `triagechain verify-custody` komutu, zinciri genesis'ten itibaren yeniden
  hesaplayıp doğruluyor; ilk bozulan kaydı (varsa) tam olarak gösteriyor.
- Zincir vaka bazlı (her `case_id`'nin kendi genesis hash'i var) — bir vakanın
  delil klasörü (dosyalar + manifest + custody log) tek başına taşınabilir,
  bağımsız olarak doğrulanabilir bir bütün oluşturuyor.

## 3. Format dönüştürme / router katmanı

- Toplanan her dosya, tipine göre otomatik olarak ilgili Eric Zimmerman
  aracına yönlendiriliyor: `$MFT` → **MFTECmd**, registry kovanları →
  **RECmd**, `.evtx` → **EvtxECmd**, prefetch → **PECmd**.
- Yönlendirme kuralları da (toplama kataloğu gibi) kod değil, veri
  (`router/catalog/tool_mapping.yaml`) — yeni bir eşleme eklemek için Python
  değiştirmek gerekmiyor.
- Araçlar TriageChain ile birlikte **dağıtılmıyor**; kullanıcı kendi kurduğu
  sürümlerin `.exe` yolunu konfigürasyonda belirtiyor. Bir araç henüz
  kurulmamışsa o artefakt "atlandı" olarak kaydediliyor, hiçbir şey çökmüyor.
- Her araç çalıştırması (başarı/hata/zaman aşımı/atlama) da chain-of-custody
  defterine yazılıyor — "kim, ne zaman, hangi araçla işledi" bilgisi sadece
  toplamada değil, işlemede de zincire giriyor.
- Her aracın stdout/stderr çıktısı diske kaydediliyor — "dış araç gerçekte ne
  yaptı" sorusunun denetim izi burada duruyor.
- **RECmd kutudan çıktığı gibi çalışıyor**: RECmd, diğer EZ araçlarının
  aksine hangi anahtar/değerlerin çıkarılacağını ayrıca ister (`--bn <toplu
  dosya>`). Bunun için topluluk standardı `DFIRBatch.reb` (MIT lisanslı,
  `EricZimmerman/RECmd` deposundan) belirli bir sürüme **sabitlenmiş** olarak
  pakete gömüldü — kullanıcının hiçbir şey ayarlaması gerekmiyor. Kendi kural
  setini kullanmak isteyen `router.recmd_batch_file` ile override edebiliyor.
  Sürüm bilerek sabit: "en güncelini indir" davranışı aynı vakayı farklı
  zamanlarda farklı kural setiyle çalıştırır, tekrarlanabilirliği bozardı.

## 4. Tespit katmanı (Sigma / Hayabusa)

- Toplanan Windows olay günlükleri (`.evtx`) **Hayabusa** ile taranıp Sigma
  kural tabanlı bulgulara dönüştürülüyor (`triagechain detect`). Yalnızca
  `event_logs` tipindeki artefaktlar taranıyor — Hayabusa registry kovanı ya
  da prefetch okumaz.
- Her bulgu (kural adı, seviye, zaman, bilgisayar, kanal, olay kimliği,
  açıklama, varsa MITRE ATT&CK etiketleri) `detection_manifest.json` içinde
  yapılandırılmış olarak duruyor; aracın ham CSV çıktısı da vakanın ağacında
  saklanıyor.
- **Çıktı ayrıştırma en iyi çaba ilkesiyle**: Hayabusa'nın CSV başlıkları
  tanınmazsa koşu düşmüyor — bulgu sayısı 0 kalıyor, ham dosyanın yolu ve bir
  uyarı kaydediliyor, sonraki dosyaya geçiliyor. Hayabusa'nın çağrı
  sözdizimi de sütun eşlemesi de kod değil veri
  (`detection/catalog/hayabusa_args.yaml`), sürüm farkı çıkarsa Python
  değiştirmeden düzeltiliyor.
- Chain-of-custody'ye **bulgu başına değil, taranan dosya başına tek özet
  olay** yazılıyor (bulgu sayısı + seviyeye göre dağılım): defter analiz
  çıktısının deposu değil, işlemin kanıtıdır. Detayların bütünlüğü,
  `detection_manifest.json`'ın SHA-256'sı kapanış olayına işlenerek zincire
  bağlanıyor.
- Hayabusa ya da Sigma kural klasörü konfigüre edilmemişse tespit "atlandı"
  olarak kaydediliyor — hiçbir şey çökmüyor.

## 5. Statik imza taraması (YARA)

- Hayabusa'dan **tamamen bağımsız**, ikinci bir tespit motoru
  (`triagechain yara-scan`) — davranışsal değil statik imza tabanlı olduğu
  için Hayabusa'nın aksine toplanan **HER** artefakt türü taranıyor (sadece
  `.evtx` değil).
- Her eşleşme (kural adı, etiketler, meta, kaynak dosya) `yara_manifest.json`
  içinde yapılandırılmış olarak duruyor.
- Yönlendirme/tespit katmanlarıyla AYNI güvenlik kuralları geçerli:
  `shell=True` yok, mutlak yollar, vakanın kendi ağacı, zaman aşımı,
  stdout/stderr diske yazımı.
- YARA kural dosyası TriageChain ile **dağıtılmıyor** (açık kaynak kural
  setlerinin çoğu kısıtlayıcı lisanslı) — kullanıcı kendi `.yar` dosyasını
  gösteriyor.
- Hem Sigma/Hayabusa HEM YARA aynı dosyayı işaretlerse bu bir **korelasyon**
  olarak ayrıca vurgulanıyor (bkz. aşağıdaki "Otomatik raporlama" bölümü) —
  iki bağımsız tekniğin aynı sonuca varması tek başına bir bulgudan daha
  güçlü bir sinyal sayılıyor.

## 6. İkinci, bağımsız bir Sigma motoru: Chainsaw

- Hayabusa'nın mimarisini birebir izleyen ama **gerçek Chainsaw**
  (WithSecure) ikilisini çağıran ikinci bir Sigma motoru
  (`triagechain chainsaw-scan`) — Hayabusa ile AYNI `Finding` şemasını
  üretiyor, ayrı bir `chainsaw_manifest.json`'a yazıyor.
- Kasıtlı mimari karar: Chainsaw'a özel bir kural klasörü **yok** —
  Hayabusa'nın kullandığı AYNI `detection.rules_dir`'i paylaşıyor. Amaç iki
  farklı kural setiyle iki farklı sonuç değil, **aynı** kural setiyle iki
  bağımsız motorun (farklı kod tabanı, farklı Sigma-yorumlayıcı) aynı
  sonuca varıp varmadığını görmek.
- Hayabusa VE Chainsaw AYNI kuralı AYNI dosyada bulursa bu bir **motor
  ittifakı** olarak rapora ve arayüze işleniyor — gerçek bir çapraz
  doğrulama sinyali.

## 7. PE davranış/yetenek analizi (capa)

- Analistin ELLE gösterdiği şüpheli yürütülebilir dosyaları (`.exe`/`.dll`,
  `collection.suspicious_binaries` ile belirtilir) **gerçek capa**
  (Mandiant/FLARE) ile davranış/yetenek analizine tabi tutuyor
  (`triagechain capa-scan`) — "bu dosya mutex açabilir", "registry
  okuyabilir" gibi statik bir yetenek envanteri çıkarıyor.
- Katalogdaki hiçbir mevcut hedef (MFT, registry, event log, prefetch)
  gerçek bir PE dosyası toplamadığı için bu özellik toplama katmanına yeni
  bir kavram ekledi: `suspicious_binaries`, diğer hedefler gibi sabit bir
  konum değil, vakaya özgü, analistin kendi seçtiği bir yol listesi.
- capa gömülü bir varsayılan kural setiyle **kutudan çıktığı gibi** çalışır
  — Hayabusa/Chainsaw/YARA'nın aksine ayrı bir kural klasörü göstermek
  zorunlu değil, sadece isteğe bağlı bir override.
- **Bilerek Yönetici Raporu'nun risk hesabına katılmıyor** ve YARA/Sigma
  ile bir korelasyon üretmiyor: capa "yetenek" tespit ediyor, kötü amaçlı
  davranış değil — gerçek, zararsız bir `.exe`'de bile onlarca capa kuralı
  eşleşiyor (bkz. `aldigim_kararlar.md`). Uzman Raporu'nda ayrı, bilgi
  amaçlı bir bölüm olarak gösteriliyor.

## 8. Otomatik raporlama

- `triagechain report` tek komutla vakanın tüm çıktılarını birleştirip iki
  dosya üretiyor: **`report.json`** (makine-okur) ve **`report.html`**
  (insan-okur, tek sayfa).
- Raporda vaka bilgisi, toplama özeti, yönlendirme özeti, tespit özetleri
  (Hayabusa VE Chainsaw ayrı ayrı — taranan dosya sayısı, toplam bulgu,
  seviyeye göre dağılım ve bulgu tabloları), YARA eşleşmeleri, capa yetenek
  eşleşmeleri, iki farklı korelasyon bölümü (Sigma+YARA kesişimi VE
  Hayabusa+Chainsaw motor ittifakı), **birleşik zaman çizelgesi**
  (MFTECmd/RECmd/EvtxECmd/PECmd çıktılarından kronolojik olarak
  birleştirilmiş — Plaso kurulamadığı için onun YERİNE, hiçbir yeni dış
  araç eklemeden; kapsamı TriageChain'in kendi dört aracıyla sınırlı,
  Plaso'nun ~600 ayrıştırıcısının tam yerini TUTMUYOR, bkz.
  `aldigim_kararlar.md`) ve gözetim zincirinin **tam** olay listesi bir
  arada duruyor.
- `report.html` **iki sekmeye** ayrılıyor (saf CSS, JS yok — internetsiz bir
  makinede de çalışır): **Yönetici Raporu** (teknik olmayan, Report'un
  gerçek sayılarından deterministik bir kurala göre hesaplanan risk
  seviyesi + düz metin özet — `reporting/executive.py`) ve **Uzman Raporu**
  (teknik detayın tamamı). Risk kuralı zincir bütünlüğünü, her iki
  korelasyonu (Sigma+YARA, Hayabusa+Chainsaw) VE her iki motorun (Hayabusa,
  Chainsaw) bulgularını hesaba katıyor — **capa bilerek hesaba katılmıyor**
  (bkz. yukarıdaki "PE davranış/yetenek analizi" bölümü).
- HTML raporun en üstünde büyük ve renkli bir **"Zincir Durumu: GEÇERLİ /
  GEÇERSİZ"** göstergesi var — zincir kırıksa hangi olayda kırıldığı da yazıyor.
- **Tamamen offline**: HTML'de harici hiçbir CDN, font, script ya da stil
  referansı yok; olay yerinde internetsiz bir makinede açılabiliyor. Dışarıdan
  gelen her metin (dosya yolu, kural adı, olay yükü) HTML kaçışından geçiyor.
- **Kısmi çalıştırmaya dayanıklı**: `route`/`detect`/`yara-scan`/
  `chainsaw-scan`/`capa-scan` hiç çalıştırılmadıysa raporun o bölümü
  "henüz çalıştırılmadı" diyor, komut çökmüyor. Yalnızca toplama manifesti
  zorunlu; o yoksa komut net bir mesajla duruyor.
- Raporun yanına **`report.json.sha256`** yazılıyor: raporun kendisinin
  sonradan değişip değişmediği, zincire hiç bakmadan `sha256sum -c` ile
  doğrulanabiliyor.
- Rapor katmanı gözetim zincirine **yazmıyor**, sadece okuyor: rapor zincirin
  o andaki fotoğrafıdır, kendi varlığıyla onu değiştirmez.

## 9. Metodoloji izlenebilirliği (tekrarlanabilirlik)

Bir bulgu ya da işlem sonucu sorgulandığında "bunu tam olarak hangi kural
seti üretti" sorusu, kod okunmadan **gözetim zinciri defterinden**
cevaplanabiliyor:

- **RECmd**: işlenen her registry kovanı için kullanılan toplu dosyanın yolu
  ve **içerik SHA-256'sı** `artifact_processed` olayına yazılıyor. Toplu dosya
  tek bir dosya olduğu için burada tam ve kesin bir hash alınabiliyor.
- **Hayabusa**: `detection_started` olayına kullanılan Sigma kural klasörünün
  yolu, toplam dosya sayısı ve bir **yapısal parmak izi**
  (`rules_fingerprint_sha256`) yazılıyor.
- **YARA**: kural dosyası TEK bir dosya olduğu için `yara_started` olayına
  doğrudan **tam içerik hash'i** (`yara_rules_sha256`) yazılıyor.
- **Chainsaw**: Hayabusa ile AYNI `rules_dir`'i kullandığı için ayrı bir
  parmak izi taşımıyor — o zaten `detection_started` olayında var.
- Hayabusa'nın parmak izi, klasördeki tüm dosyaların `(göreli yol, boyut)`
  çiftlerinin sıralı listesinden hesaplanıyor — dosya içerikleri tek tek
  hash'lenmiyor (binlerce Sigma kuralı için pahalı olurdu). **Sınırı açıkça
  belirtilmiştir:** dosya eklenmesi/çıkarılması/boyut değişikliği yakalanır,
  içeriğin aynı boyutta değiştirilmesi yakalanmaz (bkz.
  [chain_of_custody.md](chain_of_custody.md)).

## 10. Güvenlik

- **`shell=True` hiçbir yerde kullanılmıyor**: dış araçlar her zaman argüman
  listesiyle çalıştırılıyor, kabuk (shell) devreye hiç girmiyor.
- **Araç yolları mutlak olmak zorunda** (konfigürasyon aşamasında
  doğrulanıyor) — göreli yolun hangi ikiliyi çalıştıracağı belirsizdir.
- **Girdi yolu doğrulaması**: bir dosya bir araca verilmeden önce, gerçekten
  vakanın kendi yönettiği `output_dir/artifacts` ağacı altında olduğu
  doğrulanıyor — elle değiştirilmiş bir `manifest.json` bile rastgele bir
  yolu işletemez.
- **Her dış çağrının zaman aşımı var** — tek bir araç tüm koşuyu kilitleyemez.
- Konfigürasyon (case_id, hedefler, yollar) her şeyden önce doğrulanıyor;
  geçersiz bir konfigürasyonla kısmi/belirsiz bir işlem asla başlamıyor.

## 11. KAPE ile ilişki

Toplama kataloğundaki yol tanımları, kamuya açık ve açık kaynak olan
**EricZimmerman/KapeFiles** hedef tanımlarıyla kavramsal olarak uyumludur —
alınan şey sadece "hangi artefakt nerede durur" bilgisidir. KAPE'nin kendisi
(kapalı kaynak, Kroll lisanslı) hiçbir yerde çalıştırılmıyor; TriageChain'i
kullanmak için KAPE kurulumu ya da lisansı gerekmiyor.

## 12. Kullanılabilirlik

- **CLI**: `triagechain collect --config ...`, `triagechain route --config
  ...`, `triagechain detect --config ...`, `triagechain yara-scan --config
  ...`, `triagechain chainsaw-scan --config ...`, `triagechain capa-scan
  --config ...`, `triagechain report --config ...`, `triagechain
  verify-custody --log ... --case-id ...`.
- **Masaüstü arayüzü** (`triagechain-gui`): `PySide6` ile yazılmış, solda
  sabit sidebar + sağda değişen içerik alanı (`QStackedWidget`) olan tek
  pencereli bir uygulama (`src/triagechain/gui_qt/`). Bir vaka
  konfigürasyonu (`.yaml`) yüklendikten sonra YEDİ komut da (Toplamayı
  Başlat / Yönlendir / Tara / YARA Tara / Chainsaw Tara / capa Tara /
  Rapor Üret) buradan çalıştırılabiliyor; her biri ayrı bir `QThread`'de
  koştuğu için arayüz donmuyor. **Sidebar'daki sekiz sayfanın hepsi
  işlevsel** (yer tutucu sayfa yok): Dashboard (metrik kartları +
  sparkline'lar + zincir durumu rozeti), Toplanan Dosyalar, Delil Zinciri
  (tam olay listesi), Bulgular (Hayabusa + Chainsaw bulgu tabloları, YARA +
  capa eşleşmeleri, iki korelasyon vurgusu), Raporlar (Yönetici/Uzman
  sekmeleri), Vakalar (kardeş vaka klasörlerini bulma) ve Ayarlar (görünüm +
  dil) — hepsi diskteki manifest/defter dosyalarından her koşudan sonra
  **yeniden okunarak** besleniyor. Zincir kırıksa kırılma noktasından
  sonraki satırlar "Şüpheli" olarak işaretleniyor. Yönlendir/Tara/YARA/
  Chainsaw/capa/Rapor butonları `manifest.json` yoksa kapalı. Ham Python
  hata izlemesi hiçbir yerde gösterilmiyor. Arayüz kendi paleti ve
  **gömülü fontları** (Inter + JetBrains Mono, OFL lisanslı,
  `gui_qt/assets/fonts/`) ile tutarlı bir görünüm sağlıyor — hedef
  makinede bu fontların kurulu olması gerekmiyor. Eski `tkinter` arayüzü
  (`gui/app.py`) dosyası duruyor ama artık bu komuta bağlı değil.
- **Açık/koyu tema + Ayarlar sayfası** (`gui_qt/theme.py::set_mode`,
  chameleon'un aynı deseninden): Ayarlar sayfasındaki radyo düğmesiyle
  anında (pencere yeniden kurularak) geçiş yapılıyor, ayrı bir yeniden
  başlatma gerekmiyor. Açık tema renkleri GitHub Primer'in yayımlanmış
  açık tema paletinden türetildi, WCAG 2.1 kontrastı gerçek sRGB
  luminance formülüyle hesaplandı (tahmin edilmedi) — koyu temanın aynı
  disiplinle kurulmuş olmasıyla tutarlı.
- **Çok dil altyapısı** (`gui_qt/i18n.py`): Ayarlar sayfasında TR/EN/ES/
  DE/PT/FR seçenekleri var ("`<KOD> <yerel ad>`" biçiminde, örn.
  "EN English"); şu an TR + EN TAM çevrili, diğer dördü seçilebilir ama
  henüz çevrilmedi (seçilirse arayüz İngilizce'ye düşer, sayfa bunu açıkça
  belirtir). Kapsam bilerek dar: şu an sadece pencere başlığı + Ayarlar
  sayfasının kendi metni dile göre değişiyor, diğer yedi sayfanın içeriği
  henüz çevrilmedi (ayrı, daha büyük bir aşama olarak planlandı).
- **"Yeni Vaka Oluştur" sihirbazı** (`gui_qt/case_wizard.py::NewCaseDialog`):
  KAPE'nin kendi GUI'sindeki "target source"/"target destination"
  deneyimini taklit ediyor — kullanıcı vaka bilgisini yazıp kaynağı (canlı
  sistem / önceden toplanmış klasör / ZIP, ZIP'ler `zipfile` ile otomatik
  çıkartılıyor), çıktı dizinini, toplanacak artefaktları ve opsiyonel bir
  "araç klasörünü" (EZ Tools/Hayabusa/YARA/Chainsaw/capa ikilileri
  otomatik aranıp bulunuyor) seçiyor; geçerli bir `TriageChainConfig`
  arka planda üretilip diske YAML olarak yazılıyor ve hemen yükleniyor —
  kullanıcı hiçbir zaman ham YAML görmüyor/düzenlemiyor. Kaynak kökünde
  birden fazla makine klasörü bulunursa (gerçek KAPE `--zip` çıktısının
  kendi yapısı) hepsi TEK seferde ayrı birer vaka olarak oluşturulabiliyor.
- **Standalone `.exe`**: `triagechain_gui.spec` (PyInstaller `--onefile`)
  arayüzü `TriageChainKonsolu.exe` olarak paketliyor — hedef makinede
  Python kurulu olması gerekmiyor.

## 13. Bağımlılık disiplini

Dört üçüncü parti kütüphane kullanılıyor: `pydantic` (konfigürasyon
doğrulama), `PyYAML` (katalog/konfigürasyon okuma), `pywin32` (yalnızca VSS,
yalnızca Windows'ta — `pyproject.toml`'da `sys_platform == 'win32'`
işaretleyicisiyle) ve `PySide6` (masaüstü arayüzü; platform işaretleyicisi
gerekmiyor, üç işletim sisteminde de wheel'i var). Çekirdek boru hattının
kendisi (toplama, hash, chain-of-custody, yönlendirme, tespit, YARA,
Chainsaw, capa, raporlama) `PySide6`'ya hiç dokunmuyor — arayüz kaldırılsa
CLI aynen çalışır. `pywin32`, kullanıcı onayıyla alınmış **bilinçli bir
istisnadır**: VSS'i `powershell.exe` çıktısını ayrıştırarak yapan önceki
çözümün kırılganlığını tamamen ortadan kaldırıyor. Bunun dışında disiplin
aynı — CLI `click` yerine stdlib `argparse` kullanıyor; Hayabusa/Chainsaw/
YARA/capa/EZ Tools ikilileri de dağıtılmıyor, kullanıcı kendi kurduğu
sürümlerin yolunu gösteriyor. Amaç, adli bir aracın denetlenmesi gereken
yüzeyini gereksiz yere büyütmemek.
