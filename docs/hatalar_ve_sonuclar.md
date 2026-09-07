# Hatalar ve Sonuçlar

Karşılaşılan somut hataların kaydı: ne bozuktu, kök neden neydi, nasıl
düzeltildi, nasıl doğrulandı. Genel/tekrar edilebilir teknik dersler için
[ogrenilenler.md](ogrenilenler.md)'e bakın.

---

## Font gömüldükten sonra tablo satırları/sütunları özel widget'ları gösteremiyordu

**Belirti:** `theme.py`'ye gömülü Inter/JetBrains Mono fontları eklenip
gerçek metin render edilmeye başlayınca (bkz. `aldigim_kararlar.md` →
"Dashboard'un görsel yeniden tasarımı"), Delil Zinciri/Toplanan Dosyalar/
Bulgular/Vakalar tablolarındaki `setCellWidget()` ile konan özel hücreler
(ikon + iki satırlı metin, `StatusBadge`) ya tamamen görünmez (0-1px
yükseklik) ya da metni kırpılmış (`"Doğrulandı"` → `"Doğrula"`) çıkıyordu.
Offscreen render'da bulundu, gerçek ekranda henüz doğrulanmadı.

**Kök neden (iki ayrı sorun):**
1. `_style_ledger_table()`'daki `QTableWidget::item { padding: 13px 10px; }`
   kuralı, Qt'de yalnızca `QTableWidgetItem` hücrelerine değil,
   `setCellWidget()` ile konan widget'ların kullanılabilir yüksekliğine de
   uygulanıyor — `resizeRowsToContents()` bu payı hesaba katmadan satırı
   widget'ın gerçek `sizeHint()`'i kadar ayarlıyor, widget ise dolgu kadar
   sıkışıyordu.
2. `ResizeToContents` sütun modu, tıpkı satır yüksekliğinde olduğu gibi,
   `setCellWidget()` widget'larının GENİŞLİĞİNİ ölçemiyor — sütun, widget'ın
   ihtiyacından çok daha dar kalıyordu.

**Çözüm:** `_fit_rows_to_cell_widgets()` eklendi (`resizeRowsToContents()`
yerine kullanılıyor, TÜM tablolarda) — her satırın yüksekliğini hücre
widget'ının `sizeHint()`'ine `_TABLE_ITEM_VPADDING * 2` (üst+alt dolgu)
ekleyerek ayarlıyor. Sütun genişliği tarafında ise sorun HER widget
sütununda gözlenmedi (ör. tek bir `MonoLabel` taşıyan hash sütunları
`ResizeToContents` ile gerçek varyasyonlu hash'lerle gayet doğru
genişliyordu) — sadece somut olarak kırpma GÖRÜLEN üç sütun `Stretch`'e
çevrildi: Dashboard mini tablo + Delil Zinciri'nin "OLAY"/"DURUM"
(ikon+metin hücresi / `StatusBadge`) sütunları, ve Bulgular'ın
"SEVİYE"/"KAYNAK DOSYA" (`StatusBadge` / `MonoLabel`) sütunları.

**Sonuç:** Gerçek `TriageChainWindow` offscreen kurulup gerçek bir vaka
yüklenerek ekran görüntüsü alındı; "Vaka Açıldı", "Dosya Toplandı",
"Doğrulandı", "critical", "medium" artık tam ve kırpılmadan görünüyor.
**Kalan iş:** gerçek bir Windows ekranında da elle doğrulanmadı (bkz.
roadmap.md'deki tekrarlayan "offscreen testler" notu).

---

## Bilinmeyen: JetBrains Mono'da çok uzun, tek-karakterli tekrar dizileri offscreen'de tofu gösteriyor

**Belirti:** `MonoLabel("0"*64)` (64 tekrar eden "0" karakteri) izole bir
widget olarak bile render edilince tofu kutuları (□) gösteriyor; AYNI
uzunlukta ama karışık bir SHA-256 hash (`"fd7ff30...5097"`, hex harf+rakam
karışık) TAMAMEN doğru render ediliyor. Test fikstüründeki sahte hash
değerleri (`"0"*64`) bu yüzden Toplanan Dosyalar sayfasında tofu olarak
görünüyor; gerçek `hashlib.sha256(...)` çıktıları (rastgele hex) bu deseni
pratikte hiç oluşturmaz.

**Durum:** KÖK NEDEN BULUNAMADI — offscreen QPA'nin metin şekillendirme
(shaping) katmanına özgü bir kenar durumu gibi görünüyor (çok uzun aynı-
karakter dizileri için bir ligature/kerning kuralı tetikleniyor olabilir),
ama bu sadece bir hipotez. Gerçek bir Windows ekranında (DirectWrite/GDI
render yolu) hiç test edilmedi.

**Neden şimdilik ertelendi:** Gerçek veri (kriptografik hash) bu deseni
pratikte üretmez; risk düşük. Kullanıcının "0"*64 gibi bir hash'i gerçekte
GÖRMESİ, zaten hash algoritmasının kendisinin kırıldığı anlamına gelirdi.

**Kalan iş:** Gerçek bir ekranda `MonoLabel` ile uzun tekrarlı karakter
dizisi render edilip bu offscreen'e özgü mü yoksa gerçek bir font/Qt
sorunu mu olduğu doğrulanmalı.

---

## Çıktı dizini oluşturulamayınca ham `OSError` kullanıcıya sızıyordu

**Belirti:** Router katmanı, ayrıştırma çıktısı için bir dizin
(`output_dir/case_id/parsed/<arac>/<tip>`) oluşturamadığında (disk dolu, izin
yok, ya da yolun bir parçası aslında bir dosya) ham bir Python `OSError`
yukarı fırlıyordu — bu, CLI'nin `ConfigError`/`IntegrityError`/
`CustodyLedgerError` için verdiği temiz, anlaşılır mesajların aksine,
kullanıcıya çirkin bir stack trace olarak görünüyordu.

**Kök neden:** Router implementasyonunu yazan ajan bunu bilinçli bir tasarım
kararı olarak bırakmıştı ("bu olumcul sayilir ve OSError bilerek yukari
birakilir") ama `core/errors.py`'deki tipli hata hiyerarşisine yeni bir tip
eklemek görev kapsamının dışında bırakılmıştı — sonuç olarak hata ölümcül
sayılması doğruydu, ama kullanıcıya sunuluş şekli projenin geri kalanıyla
tutarsızdı.

**Çözüm:** `core/errors.py`'ye `RouterError(TriageChainError)` eklendi;
`router/runner.py`'de `output_dir.mkdir()` çağrısı `try/except OSError` ile
sarılıp `RouterError`'a çevrildi (custody katmanındaki `CustodyLedgerError`
sarma deseniyle birebir aynı); `cli/main.py`'nin `main()` fonksiyonuna
`except RouterError` eklenip diğer hata tipleriyle aynı temiz mesaj +
çıkış kodu 1 davranışına kavuşturuldu.

**Sonuç:** "parsed" adında önceden bir DOSYA oluşturup (dizin değil) mkdir'in
gerçekten başarısız olmasını sağlayan bir regresyon testi eklendi
(`test_output_dir_creation_failure_is_fatal_router_error`) — `RouterError`
fırlatıldığı ve `subprocess.run`'ın hiç çağrılmadığı doğrulandı. Tüm test
takımı (38 test) yeşil.

---

## Hayabusa argüman şablonunda var olmayan bir alt komut varsayılmıştı

**Belirti:** `detection/catalog/hayabusa_args.yaml`'daki ilk şablon
`csv-timeline -f {input} -r {rules_dir} -o {output_csv} --quiet` idi —
Hayabusa kurulu olmadığı için bu tahminle ilerlenmişti.

**Kök neden:** Kullanıcının bilgisayarında zaten kurulu bir Hayabusa 1.4.1
bulunup `hayabusa.exe --help` ile gerçek sözdizimi kontrol edildiğinde, bu
sürümün HİÇBİR alt komut (subcommand) kullanmadığı, düz bayraklarla
çalıştığı ortaya çıktı (`hayabusa.exe -f file.evtx [OPTIONS]`) — `csv-timeline`
diye bir alt komut YOK. `-f`/`-r`/`-o`/`-q` bayraklarının kendisi doğruydu,
sadece baştaki `csv-timeline` fazlalıktı.

**Çözüm:** `hayabusa_args.yaml`'dan `"csv-timeline"` satırı kaldırıldı;
ilgili testteki (`test_detection_runner.py`) sabit "csv-timeline" varsayımı
da düzeltildi.

**Sonuç:** Gerçek `hayabusa.exe --help` çıktısıyla karşılaştırılıp
doğrulandı. Tam bir gerçek tarama (rules dizini) henüz tamamlanamadı —
kullanıcının yerel kurulumundaki `rules/hayabusa`, `rules/sigma` klasörleri
boş git submodule'ler (0 `.yml` dosyası), bu yüzden gerçek bir `.evtx`'e
karşı çalıştırma Rust tarafında bir panic ile sonuçlandı. Bu, TriageChain'in
kodundaki bir hata DEĞİL — kullanıcının Hayabusa kurulumunun kendi
eksikliği (`git submodule update --init` gerekiyor). CSV başlıklarının
(`Timestamp`/`RuleTitle`/vb.) gerçek karşılığı bu yüzden hâlâ doğrulanamadı,
`csv_columns` eşlemesi hâlâ varsayım olarak işaretli kalıyor. Tüm test
takımı (58 test) yeşil.

---

## `vssadmin create shadow` gerçek bir Windows makinesinde çalışmıyordu

**Belirti:** Faz 1'de tasarlanan VSS erişimi `vssadmin create shadow
/for=C:` komutuna dayanıyordu. Kullanıcı Yönetici (UAC) yetkisiyle gerçek bir
canlı test yaptırınca, bu komut **doğrudan komut satırından çalıştırıldığında
bile** `Error: Invalid command.` ile reddedildi — `vssadmin`'in kendi yardım
metni artık desteklenen komutlar arasında "Create Shadow"u hiç LİSTELEMİYOR
(sadece Delete/List/Resize var).

**Kök neden:** Microsoft, `vssadmin create shadow`'u istemci (client) Windows
sürümlerinde (fidye yazılımı kötüye kullanımına karşı) kaldırdı. Bu, Faz 1
tasarımının kontrol edemediği bir varsayımdı (o an gerçek bir Windows
makinesinde test edilememişti, bkz. o zamanki "Sırada" maddesi) — koddaki
hata değil, dış dünyanın (işletim sistemi davranışının) değişmiş olması.
`vssadmin delete shadows` ise hâlâ çalışıyor (kaldırılmadı) — sadece
OLUŞTURMA yolu bozuktu.

**Çözüm:** `vss_snapshot.py`'nin golge kopya OLUŞTURMA kısmı, `vssadmin`
yerine WMI'nin `Win32_ShadowCopy.Create()` metodunu `powershell.exe`
üzerinden çağıracak şekilde değiştirildi (`pywin32`/COM'a hâlâ gerek yok —
yine sadece Windows'a gömülü bir programı subprocess ile çağırıyoruz).
Çıktı ayrıştırması da `vssadmin`'in dile göre değişen serbest metnini regex
ile avlamak yerine, PowerShell komutunun kendisinin ürettiği sabit
`ANAHTAR=deger` satırlarını okuyacak şekilde yeniden yazıldı — daha kırılgan
olmayan bir format. SİLME kısmı değiştirilmedi (`vssadmin delete shadows`
hâlâ çalışıyor).

**Sonuç:** Kullanıcının kendi bilgisayarında, gerçek bir Yönetici (UAC)
oturumunda uçtan uca doğrulandı: gölge kopya oluşturuldu, yol çevrildi,
gölge kopyadan gerçek bir dosya (42 bayt) okundu, `with` bloğu bitince
temizlendi (`vssadmin list shadows` sonrasında hiçbir kalıntı yok). Bu
modül için daha önce hiç birim testi yoktu (Faz 1'in entegrasyon testi
bilinçli olarak `requires_vss: false` hedeflerle sınırlıydı) —
`tests/unit/test_vss_snapshot.py` eklendi (7 test, mock'lanmış
`subprocess.run` ile: başarılı oluşturma+silme, WMI hatası, zaman aşımı,
`powershell` bulunamaması, silme hatasının yutulmayıp sadece loglanması).
Toplam test sayısı 67'den 74'e çıktı.

**Sonraki gelişme (bu çözüm artık geçerli değil):** `powershell.exe` +
`ANAHTAR=deger` ayrıştırması, kullanıcının açık onayıyla `pywin32`
(`win32com.client`) üzerinden **doğrudan** WMI çağrısına taşındı. Metin
ayrıştırma (dolayısıyla `parse_create_output`/`_build_create_script`/
`_KV_PATTERN`) tamamen kaldırıldı; silme de artık `vssadmin delete shadows`
değil, WMI örneğinin kendi `Delete_()` metodu. Kod deseni gerçek makinede,
gerçek Yönetici (UAC) yetkisiyle önceden doğrulandı. Yukarıdaki `vssadmin
create shadow` bulgusu hâlâ geçerli — sadece onun yerine konan çözüm değişti.
Detaylar ve gerekçe: `docs/aldigim_kararlar.md`.

---

## Registry kovanları LOG dosyaları olmadan toplanıyordu, RECmd "dirty hive" ile reddediyordu

**Belirti:** Kullanıcının gerçek (KAPE ile toplanmış, saldırıya uğramış) bir
laboratuvar verisiyle RECmd'i gerçek bir SYSTEM kovanına karşı çalıştırınca:
"Registry hive is dirty and no transaction logs were found ... Aborting!!"
hatasıyla hiçbir çıktı üretmeden durdu.

**Kök neden:** Canlı alınan bir registry kovanı neredeyse hiçbir zaman temiz
kapatılmamıştır (dirty) — Windows, son değişiklikleri hive dosyasının
kendisine değil, yanındaki `.LOG1`/`.LOG2` işlem (transaction) log
dosyalarına yazar. RECmd (ve RegistryExplorer) bu LOG dosyalarını "replay"
edebilmek için hive ile AYNI dizinde bulmayı bekliyor. TriageChain'in
toplama kataloğu (`default_targets.yaml`) sadece çıplak hive dosyasını
(`SYSTEM`, `SAM`, ...) topluyordu, yanındaki LOG dosyalarını hiç almıyordu.

**Çözüm:** `registry_system`/`registry_sam`/`registry_security`/
`registry_software` hedeflerinin `paths` listesine `.LOG1`/`.LOG2` glob'ları
eklendi — aynı hedefin altında toplandıkları için hive ile AYNI çıktı
dizinine düşüyorlar (RECmd'in bulabilmesi için şart). Bu, router tarafında
yeni bir sorun açtı: LOG dosyaları da `registry_system` tipiyle toplandığı
için router onları da BAĞIMSIZ birer RECmd girdisi sanıp ayrı ayrı
çalıştırmaya çalışırdı — anlamsız/hatalı bir çağrı olurdu. `router/runner.py`'ye,
dosya adı `.LOG1`/`.LOG2` ile bitiyorsa hiçbir araca gönderilmeden
"atlandı" olarak kaydedilmesini sağlayan bir kontrol eklendi.

**Sonuç:** LOG dosyaları gerçek zip'ten çıkarılıp eklenince RECmd aynı
kovanı sorunsuz işledi (gerçek çıktı: 1.3 MB CSV). Yeni bir regresyon testi
(`test_hive_transaction_log_files_are_never_routed_on_their_own`) hem LOG
dosyalarının atlandığını hem de gerçek hive için `subprocess`in doğru
çağrıldığını doğruluyor. Toplam test sayısı 74'ten 75'e çıktı.

---

## Operasyonel notlar (hata değil, tekrar karşılaşılabilecek sürtünmeler)

- **"Ücretsiz" ile "açık kaynak" karıştırılabiliyor**: KAPE (Kroll) ücretsiz
  dağıtılıyor ama kapalı kaynak, kendi EULA'sıyla geliyor — proje planlaması
  sırasında bu ayrım netleşene kadar "KAPE'yi de projeye gömelim, bağımlılığı
  azaltırız" gibi yanlış bir varsayıma yol açtı. Sadece hedef *tanımları*
  (`EricZimmerman/KapeFiles`) ayrı ve gerçekten açık kaynak. Bir aracın
  "ücretsiz" olması "kaynağı açık/dağıtılabilir" anlamına gelmiyor; ikisi
  ayrı ayrı kontrol edilmeli.
- **EvtxECmd ve MFTECmd gerçek ikililerle DOĞRULANDI, sözdizimi birebir
  doğru çıktı**: Kullanıcının gerçek (KAPE ile toplanmış, saldırıya uğramış
  bir laboratuvardan) `Security.evtx` ve `$MFT` dosyalarına karşı gerçek
  `EvtxECmd.exe -f <dosya> --csv <dizin>` ve `MFTECmd.exe -f <dosya> --csv
  <dizin>` çalıştırıldı — ikisi de exit code 0 ile gerçek CSV ürettiği
  (sırasıyla 10.4 MB / 123.640 MFT kaydından 66 MB) doğrulandı,
  `tool_mapping.yaml` değişiklik gerektirmedi.
- **RECmd sözdizimi EKSİKTİ, gerçek testte bulundu — ÇÖZÜLDÜ**:
  `RECmd.exe -f <hive> --csv <dizin>` (mevcut şablon) gerçek bir SYSTEM
  kovanına karşı "One of the following switches is required: --sa | --sk |
  --sv | --sd | --ss | --kn | --Base64 | --MinSize | --bn" hatasıyla
  reddedildi — MFTECmd/EvtxECmd'nin aksine RECmd, hangi anahtar/değerin
  aranacağını ya da hangi toplu (batch, `--bn <dosya>`) tanımın
  kullanılacağını AYRICA bilmek istiyor. `--bn <RegistryASEPs.reb gibi genel
  bir toplu dosya>` ile gerçek kovana karşı denendiğinde çalıştığı
  doğrulandı. **Sonradan çözüldü:** "bu toplu dosyalar EZ Tools'un kendi ayrı
  lisanslı varlıkları, gömülemez" varsayımı da kontrol edilince yanlış çıktı —
  RECmd deposunun tamamı (`BatchExamples/` dahil) **MIT lisanslı**. Bu yüzden
  standart `DFIRBatch.reb`, belirli bir sürüme sabitlenmiş olarak pakete
  gömüldü (`router/catalog/recmd_batch/`, kaynak bilgisi `PROVENANCE.md`'de);
  `RouterConfig`'e eklenen `recmd_batch_file` alanı ise zorunlu bir ayar değil,
  yalnızca bir override. Ders: bir dosyanın "başka birinin aracına ait olması"
  onun dağıtılamaz olduğu anlamına gelmiyor — lisansına bakmak yeterliydi
  (KAPE'de tam tersi yönde aynı hatayı yapmıştık: "ücretsiz" görünen şey
  kapalı kaynak çıkmıştı).
- **Hayabusa'nın CLI sözdizimi SÜRÜMLER ARASI değişiyor, gerçek CSV çıktısı
  ARTIK DOĞRULANDI**: Kullanıcının eski (1.4.1) kurulumu hiç alt komut
  kullanmıyordu; GitHub'dan indirilen güncel sürüm (4.0.0) ise
  `dfir-timeline` alt komutunu ve etkileşimli sihirbazı kapatan `-w`
  bayrağını gerektiriyor (bkz. `detection/catalog/hayabusa_args.yaml`'daki
  güncel not) — şablon buna göre güncellendi. Kullanıcının gerçek (saldırıya
  uğramış) laboratuvar verisine karşı çalıştırılınca **5.124 gerçek bulgu**
  (12 high, 135 medium, 1.438 low, 3.539 informational) üretti; CSV başlığı
  tam olarak varsayılan `Timestamp,RuleTitle,Level,Computer,Channel,EventID,
  RecordID,Details,ExtraFieldInfo,RuleID` çıktı — `csv_columns`'daki ilk
  adaylarımız (`Timestamp`/`RuleTitle`/`Level`/`Computer`/`Channel`/
  `EventID`/`Details`) HEPSİ birebir eşleşti, YAML değişikliği gerekmedi.
  Projenin kendi `_parse_findings` fonksiyonu bu gerçek CSV'ye karşı
  çalıştırılıp 5.124 bulgunun tamamının doğru ayrıştırıldığı, seviye
  dağılımının Hayabusa'nın kendi özetiyle birebir uyuştuğu doğrulandı.
- **VSS gerçek bir Windows Yönetici oturumunda test edildi ve bir hata
  bulunup düzeltildi** — bkz. yukarıdaki "`vssadmin create shadow` gerçek
  bir Windows makinesinde çalışmıyordu" kaydı. Artık çözüldü ve doğrulandı,
  bu roadmap maddesi kapandı.
- **Windows'ta Türkçe karakter içeren dosya yollarını ELLE YAZMAKTAN
  kaçının**: Bu oturumda "adli bilişim materyalleri" gibi bir klasör adını
  komut içine kendim yazdığımda (Bash'te de, bir defasında PowerShell'de de)
  yol çözümlemesi ["ş" harfinin farklı bir Unicode normalizasyon biçimiyle
  kodlanması ihtimaline bağlı olarak] tutarsız şekilde başarısız oldu; aynı
  yol `Get-ChildItem`/`find` ile ORTAMDAN OKUNUP bir değişkene atanınca
  sorunsuz çalıştı. Genel kural: nizami olmayan (non-ASCII) bir yol
  segmentini asla elle yazmayın, her zaman dizin listeleme/arama aracıyla
  bulup değişkende taşıyın.
- **YARA gerçek ikiliyle (4.5.5) doğrulandı**: `yara_args.yaml`'daki argüman
  şablonu ve stdout satır deseni, gerçek `yara64.exe`'yi gerçek bir `.yar`
  kuralı ve gerçek bir hedef dosyaya karşı çalıştırarak doğrulandı — eşleşme
  satırının biçimi (`KuralAdı [etiketler] [meta] dosya_yolu`) belgeye
  güvenilmeden gözlemlenerek regex'e yazıldı.
- **Chainsaw'ın "binary-only" ve "full bundle" zip'leri farklı dosya adları
  kullanıyor**: Sadece ikiliyi içeren zip `chainsaw.exe` veriyor, kurallar +
  örneklerle gelen "full bundle" zip ise platforma özel adlandırılmış bir
  ikili (`chainsaw_x86_64-pc-windows-msvc.exe`) içeriyor. İlk denemede
  `chainsaw.exe` beklenip "dosya/dizin bulunamadı" hatası alındı; gerçek
  dosya adı dizin listelemesiyle bulunup düzeltildi. Ders: bir aracın GitHub
  Release sayfasındaki birden fazla zip'i "aynı içerik, farklı sıkıştırma"
  sanmayın — içerik/dosya adları farklı olabilir, indirdikten sonra gerçekten
  listeleyin.
- **Elle yazılmış minimal bir Sigma kuralı Chainsaw'a yüklenmedi, resmi
  örnek veriyle ANINDA çalıştı**: bkz. `ogrenilenler.md` → "Tanımadığın bir
  DSL'i elle yazıp debug etmek yerine aracın KENDİ resmi örneğini kullan".
  Gerçek Chainsaw v2.16.5, gerçek EVTX-ATTACK-SAMPLES + gerçek SigmaHQ
  kurallarına karşı 8 gerçek tespit üretti; bu gerçek JSON çıktısı
  `test_chainsaw_runner.py`'nin sahte kaydının (`FAKE_JSON_RECORD`) temeli
  oldu.
- **Test bug: `argv[-1]` girdi yolunun SON eleman olduğunu varsaydı, ama
  değildi**: `chainsaw_args.yaml` şablonunun son elemanı `--skip-errors`
  bayrağı, girdi dosyası (`{input}`) ortada bir yerde. `test_non_zero_exit_
  code_is_an_error_and_run_continues` testi `"Bad.evtx" in argv[-1]` ile
  hata enjekte etmeye çalışıyordu ama bu koşul asla doğru olmuyordu — test
  YANLIŞ-NEGATİF veriyordu (`len(detection.errors) == 1` bekleniyor, `0`
  geliyordu, ama assertion hatası fark edilene kadar test "geçiyormuş" gibi
  görünmüyordu, tam tersi başarısız oluyordu ve kök neden bulunana kadar
  şüpheli kaldı). Düzeltme: `any("Bad.evtx" in part for part in argv)` —
  argv şablonundaki değişkenin TAM OLARAK hangi pozisyonda olduğunu asla
  varsaymayın, şablonun kendisine bakın.
