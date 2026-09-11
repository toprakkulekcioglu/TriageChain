# Aldığım Kararlar

Bu proje geliştirilirken benim (Claude) verdiğim, kullanıcının her defasında
onayını almadığım ama gerekçesi olan teknik/mimari kararların kaydı. Amaç:
"neden böyle yapıldı" sorusuna gelecekte (kod okunarak değil) doğrudan bu
dosyadan cevap bulunabilmesi. Yeni bir karar aldıkça buraya yeni bir madde
ekleniyor — bu dosya sürekli büyüyecek şekilde tasarlandı, geçmiş kayıtlar
silinmiyor/değiştirilmiyor.

---

## VSS için gerçek zaman aşımı: ayrı daemon thread + `join(timeout)`

**Karar:** `VssSnapshot`'ın hem golge kopya OLUŞTURMA (`__enter__`) hem
SİLME (`__exit__`) çağrıları artık ayrı bir daemon thread'de çalıştırılıp
`threading.Thread.join(timeout)` ile bekleniyor (`_run_with_timeout()`).
Thread `pythoncom` kuruluysa kendi COM apartmanını (`CoInitialize`/
`CoUninitialize`) açıp kapatıyor — WMI nesneleri apartman-bağlı olduğu
için oluşturma/sorgu/silme AYNI thread içinde kalıyor, sonuç ana thread'e
sadece bir sözlük üzerinden taşınıyor.

**Gerekçe:** Roadmap'te ("VSS için gerçek zaman aşımı") zaten bilinen bir
sınırlama olarak not düşülmüştü: `timeout` parametresi imzada duruyordu
ama hiç kullanılmıyordu. Python thread'leri ZORLA durdurulamadığı için bu
gerçek bir "iptal" değil — zaman aşımında kontrol çağırana geri veriliyor
ama arka plan thread'i (COM kendi apartmanında) çalışmaya devam edebilir.
Bu, YETİM bir gölge kopya bırakma riski taşır; kullanıcıya `vssadmin list
shadows` ile elle kontrol önerisi veriliyor. Roadmap'in kendi notu da
zaten bu riski kabul edip "gerçekten gerekirse" bu deseni öneriyordu.

**Doğrulama:** Gerçek bir askıda-kalma senaryosu simüle eden 2 yeni test
eklendi (`test_enter_raises_collection_error_on_real_timeout`,
`test_exit_delete_timeout_is_logged_not_raised`) — sahte WMI çağrısı
`time.sleep()` ile yavaşlatılıp gerçekten zaman aşımına uğratıldı (mock'un
kendisi "yavaş" davranmıyor, sadece hata dönmüyor gibi davranmak yerine
GERÇEKTEN uzun sürüyor). Toplam 131 test yeşil.

---

## Custody defterine çoklu-yazıcı desteği: stdlib dosya kilidi, yeni bağımlılık yok

**Karar:** `custody/storage.py`'ye `locked()` eklendi — Windows'ta
`msvcrt.locking`, POSIX'te `fcntl.flock` (ikisi de STDLIB) ile ayrı bir
`.jsonl.lock` dosyası üzerinden özel (exclusive) kilit tutuyor.
`CustodyLedger.append_event()` artık `last_hash()` okuması ile
`append_line()` yazmasının TAMAMINI bu kilit içinde, atomik olarak yapıyor.
Okuma (`read_lines`/`verify_chain`) BİLEREK kilitsiz bırakıldı — log
dosyasının kendisi değil, ayrı bir `.lock` dosyası kilitlendiği için
doğrulama hiçbir zaman bir yazıcının arkasında beklemiyor.

**Gerekçe:** Roadmap'te bilinen bir sınırlama olarak duruyordu: "v0.1'de
bir vaka için tek bir toplama/yönlendirme süreci varsayılıyor (dosya
kilidi yok); eşzamanlı birden fazla süreç senaryosu ortaya çıkarsa ele
alınacak." Artık GUI ile CLI'nin AYNI vakaya aynı anda yazması (örn.
kullanıcı GUI'de "Tara" çalıştırırken elle `triagechain report` çağırması)
gerçek bir senaryo — kilit olmadan iki yazıcı aynı `prev_hash`'i okuyup
zinciri ÇATALLAYABİLİRDİ.

**Neden yeni bir bağımlılık eklenmedi:** `msvcrt`/`fcntl` ikisi de Python
stdlib'inde — projenin "üçüncü parti bağımlılıktan kaçın" ilkesiyle tam
uyumlu, `filelock` gibi bir pip paketine gerek kalmadı.

**Doğrulama:** `test_concurrent_writers_do_not_fork_the_chain` eklendi —
8 thread, her biri KENDİ `CustodyLedger` örneğiyle (gerçek ayrı süreçleri
simüle etmek için paylaşılan bir Python nesnesi değil, dosya sistemi
seviyesindeki kilidin kendisi test ediliyor) aynı deftere 10'ar olay
yazıyor; sonuç zincir 80 olayla GEÇERLİ çıkıyor, çatallanma yok. 132 test
yeşil.

---

## Çoklu disk desteği: SADECE $MFT, katalog mekanizmasına dokunulmadan

**Karar:** `collection.additional_volumes: list[str]` config alanı eklendi
(örn. `["D:", "E:"]`). Her ek birim için `_collect_additional_volumes()`,
o birime özel AYRI bir `VssSnapshot(volume=...)` açıp `$MFT`'sini topluyor
— mevcut `_collect_target()` fonksiyonu AYNEN yeniden kullanılıyor (elle
bir `ResolvedTarget` kurup besliyor), ikinci bir toplama/hash/hata-kaydı
yolu YOK.

**Gerekçe:** Roadmap'te not düşülmüştü: "$MFT her NTFS biriminde ayrı
ayrı var, v0.1 sadece sistem diskini alıyor." Registry kovanları/event
log/prefetch gibi diğer hedefler Windows KURULUMUNA özgü (sistem
diskinden başka bir yerde anlamlı bir karşılıkları yok) — bu yüzden
kasıtlı olarak SADECE `$MFT` çoklu-disk'e açıldı, katalog mekanizmasının
`%SystemDrive%` varsayımına dokunulmadı (registry/event log/prefetch
`additional_volumes`'tan ETKİLENMİYOR).

**Doğrulama:** `test_multi_disk_collection.py` — sahte bir `VssSnapshot`
ile (gerçek WMI'ye ihtiyaç yok, CI Linux'ta da çalışır) hem başarılı
toplama hem "birim erişilemez" senaryosu (olumcul değil, sadece o birim
için hata) test edildi; ayrıca sürücü harfi doğrulaması (`"D:"` kabul,
`"not-a-drive"` reddedilir) ve normalizasyon (`"d:\\"` → `"D:"`) ayrı
testlerle kapsandı. 136 test yeşil.

---

## MITRE ATT&CK etiketleri eklendi, CVE entegrasyonu eklenmedi

**Karar:** Kullanıcı "CVE kodları ve MITRE ATT&CK verisi eklemeli miyiz"
diye sordu. Araştırdım (bkz. Sources aşağıda): Sigma kuralları zaten kendi
metadatasında MITRE ATT&CK teknik/taktik etiketleri taşıyor
(`tags: [attack.t1055, ...]`), Hayabusa bunu CSV'ye `MitreTactics` gibi bir
sütun olarak yansıtabiliyor. Bu yüzden `Finding.mitre_tags` alanı eklendi
(`detection/models.py`, `detection/catalog/hayabusa_args.yaml`,
`detection/runner.py`) — sütun yoksa boş kalır, hiçbir şey uydurulmaz, yeni
bağımlılık/ağ çağrısı YOK. CVE tarafında ise **eklemedim**: bu proje bir
zafiyet tarayıcısı değil, toplanan artefaktlardan (MFT/registry/event log)
zaten-gerçekleşmiş-ihlal göstergesi çıkarıyor — CVE'nin gerçek/uydurmasız
bağlanabileceği bir veri kaynağı (ör. yüklü yazılım envanteri + zafiyet
veritabanı eşlemesi) şu an mimaride yok.

**Gerekçe:** Projenin temel ilkesi "hiçbir şey uydurulmaz, sadece diskteki
gerçek veri okunur" ([[project_triagechain]]). MITRE ATT&CK için gerçek bir
veri kaynağı zaten var (Sigma/Hayabusa), CVE için yok — üretmek CVE
alanlarını boş/anlamsız bırakır ya da (daha kötüsü) sahte doldurmaya
zorlar. Ayrıca canlı bir CVE/MITRE API çağrısı, raporun "tamamen offline"
ilkesini (bkz. Faz 5, `roadmap.md`) bozardı; Sigma metadata yaklaşımı ağ
çağrısı gerektirmiyor.

**Kaynaklar:** [Sigma Rules Explained](https://www.socsimulator.com/blog/sigma-rules),
[SigmaHQ/sigma](https://github.com/sigmahq/sigma) — `tags:` alanının
MITRE ATT&CK teknik/taktik eşlemesi için kullanıldığını doğruluyor.

---

## YARA entegrasyonu: kural dosyası vendor edilmedi, CLI-BYO deseni korundu

**Karar:** YARA, Hayabusa ile BİREBİR aynı mimari desende eklendi:
`detection.yara_path`/`yara_rules_file` config alanları, `subprocess`
çağrısı (asla `shell=True`, argümanlar liste, mutlak yollar, zaman aşımı),
kendi manifesti (`yara_manifest.json`, `YaraManifest`/`YaraMatch`
modelleri). Yaygın açık kaynak YARA kural setlerinden biri (örn.
Yara-Rules/rules) PROJEYE VENDOR EDİLMEDİ.

**Gerekçe:** Yara-Rules/rules GNU GPLv2 lisanslı — bunu pakete gömmek
lisans uyumluluğu sorusu açardı (bu proje şu an hiçbir GPL bağımlılığı
taşımıyor). Ayrıca proje zaten kurulu bir ilke olarak "araç TriageChain
ile dağıtılmaz, kullanıcı kendi kurduğu/yazdığı kural setinin yolunu
bildirir" desenini benimsiyor (bkz. Hayabusa/RECmd/EvtxECmd/MFTECmd —
hiçbiri vendor edilmedi). Entegrasyonu GERÇEK bir ikiliye karşı test
etmek için resmi `VirusTotal/yara` GitHub sürümünden (BSD-3-Clause,
`v4.5.5`, `yara-4.5.5-2368-win64.zip`) `yara64.exe` indirilip elle
yazılmış, orijinal (lisans sorunu olmayan) 2 kuralla gerçek bir eşleşme +
gerçek bir eşleşmeme senaryosu doğrulandı; bu ikili/kurallar depoya
commit EDİLMEDİ, sadece geçici test ortamında kullanıldı.

**Alternatif (kullanılmadı):** Yara-Rules/rules ya da benzer bir GPLv2/
DRL-lisanslı seti pakete gömmek — daha "hazır" bir başlangıç seti
sağlardı ama lisans karmaşası ve "araç dağıtılmaz" ilkesiyle çelişki
yaratırdı.

---

## VSS erişimi: `pywin32`/COM yerine `vssadmin` subprocess çağrısı

**Karar:** Kilitli Windows dosyalarına (`$MFT`, registry kovanları) erişim
için `pywin32` ile COM API'si değil, `subprocess` ile `vssadmin
create/delete shadow` komut satırı kullanıldı.

**Gerekçe:** Kullanıcı projede "bağımlılıktan kaçınalım" tercihini açıkça
belirtti. `pywin32` yeni bir üçüncü parti bağımlılık eklerken, `vssadmin`
zaten Windows'ta hazır bulunan bir sistem aracı — aynı işi ek bir pakete
ihtiyaç duymadan yapıyor.

**Alternatif (kullanılmadı):** `pywin32` ile doğrudan VSS COM API'sini
kullanmak — daha "temiz"/programatik olurdu ama yeni bağımlılık demekti.

---

## Dashboard'un görsel yeniden tasarımı: font sorunu tespit edildi ~~düzeltmesi ertelendi~~ ÇÖZÜLDÜ

**Karar:** Kullanıcının onayladığı referans tasarıma göre `theme.py`
(RADIUS 5→14, RADIUS_SM=10, CARD_PADDING/CARD_GAP 20/16→24/24, büyük metrik
değeri 30px/500→36px/700), `widgets.py` (Card başlığı büyük beyaz başlık,
StatusBadge daha dolgun pill, Sparkline'a glow) ve `main_window.py`
(sidebar'a ikon+"GENEL" bölüm başlığı, 7 yeni SVG ikon) güncellendi.
Kullanıcı gerçek masaüstünde çalıştırınca fontların (Inter/JetBrains Mono)
beklenenden çok farklı göründüğünü bildirdi — muhtemelen bu iki font
sistemde kurulu değil ve Qt sessizce bir yedek fonta düşüyor. Kullanıcının
kendi talimatıyla ("tasarıma sonradan döneriz") bu sorunun kök nedenini
araştırmak/düzeltmek bilinçli olarak ERTELENDİ, öncelik placeholder
sayfaların işlevselleştirilmesine kaydırıldı.

**Gerekçe:** `RADIUS`/`CARD_PADDING` gibi jeton değişiklikleri anında/güvenle
uygulanabilir tasarım kararlarıydı; font kurulumu ise kullanıcının
makinesine özel bir ortam sorunu olabilir ve kullanıcı bunu şimdilik
kapsam dışı bıraktı.

**Kalan iş (sonraya):** ~~`theme.py`'deki `FONT_UI`/`FONT_MONO` gerçekten
sistemde kurulu mu doğrulanmalı (`QFontDatabase.families()`); değilse ya
fontlar paketle birlikte gömülüp `QFontDatabase.addApplicationFont()` ile
yüklenmeli ya da gerçekten kurulu bir sistem fontuna geri dönülmeli.~~

**ÇÖZÜLDÜ (sonraki turda):** `ui-ux-pro-max` tasarım verisi de Inter +
JetBrains Mono eşleştirmesini bu tür bir güvenlik/DFIR aracı için ayrıca
doğruladı (JetBrains Mono özellikle "security tools" için öneriliyor) —
yani sorun font SEÇİMİNDE değil, KURULUMUNDAYDI. Çözüm: resmi GitHub
release'lerinden (Inter v4.1, JetBrains Mono v2.304 — ikisi de OFL 1.1)
kullanılan 4 ağırlık (Regular/Medium/SemiBold/Bold) indirilip
`gui_qt/assets/fonts/`'a gömüldü (bkz. oradaki `PROVENANCE.md`),
`theme.load_embedded_fonts()` eklendi ve `app.py:main()` başında
`QFontDatabase.addApplicationFont()` ile yükleniyor. Artık hangi
makinede çalıştığından bağımsız olarak hep aynı font kullanılıyor —
gerçek offscreen render ile doğrulandı (`QFontDatabase.families()`'te
ikisi de göründü, ekran görüntüsünde gerçek Inter/JetBrains Mono
render edildi).

---

## KAPE'nin kendisi değil, KapeFiles hedef tanımları kullanıldı

**Karar:** Toplama kataloğu (`collection/catalog/default_targets.yaml`),
KAPE.exe'yi hiç çağırmadan, sadece KAPE'nin açık kaynaklı hedef tanımları
(`EricZimmerman/KapeFiles`) referans alınarak elle yazıldı.

**Gerekçe:** KAPE'nin kendisi ücretsiz ama **kapalı kaynak** (Kroll EULA'sı
ile dağıtılıyor) — kullanıcı başta "KAPE açık kaynaklı, hepsini oradan
çekelim" varsayımıyla geldi, bu yanlıştı. KapeFiles deposu ayrı ve gerçekten
açık kaynak (sadece yol/tanım verisi). Bu şekilde hem "KAPE'nin bildiği
hemen hemen her artefakt" kapsamına yakın bir kapsam elde edildi hem de
KAPE kurulumu/lisansı gerektiren bir bağımlılık oluşmadı.

---

## Config doğrulama için `pydantic` seçildi (stdlib `dataclasses` değil)

**Karar:** Konfigürasyon şeması (`config/schema.py`) `pydantic` ile
yazıldı; elle `if/raise` doğrulamalarıyla stdlib `dataclasses` değil.

**Gerekçe:** Profesyonel DFIR yazılımlarında (Volatility 3, Autopsy, Plaso
gibi) "güven-kritik çekirdek" (hash hesaplama, chain-of-custody) stdlib'e
yakın/az kod ile tutulur, ama "çevresel" katmanlar (config okuma, CLI, rapor
üretimi gibi) için olgun kütüphaneler kullanmak normaldir. Config
doğrulama tam olarak bu çevresel katmana giriyor — pydantic hash-chain'e
dokunmuyor, sadece daha az kod ve daha iyi hata mesajı sağlıyor. Kullanıcıya
bu tradeoff anlatılıp onay alındıktan sonra uygulandı (tek üçüncü parti
bağımlılık kararı kullanıcıya doğrudan soruldu, gerisi bana bırakıldı).

---

## Router'da (ve sonraki her dış-araç katmanında) 4 güvenlik kuralı zorunlu

**Karar:** Dış program (subprocess) çağıran her katman şu 4 kuralı
uygulamak zorunda: (1) `shell=True` asla, argüman listesi kullan; (2) araç
yolu config'de mutlak olmalı; (3) girdi dosyası yolu, `Path.resolve()` +
`is_relative_to()` ile vakanın kendi çıktı ağacı içinde olduğu doğrulanmadan
hiçbir subprocess'e verilmez; (4) her çağrının `timeout=` değeri olmalı.

**Gerekçe:** Bir adli bilişim aracının en riskli yüzeyi, kendi ürettiği
ama sonradan elle değiştirilebilecek ara veriye (manifest.json gibi) körü
körüne güvenip onu bir dış programa geçirmesidir. Bu 4 kuralın HİÇBİRİ tek
başına yeterli değil (bkz. `docs/ogrenilenler.md`), üçü/dördü birlikte
gerekiyor. Bu kural şu an sadece router'da değil, ileride yazılacak her
subprocess-çağıran katmanda (detection/Hayabusa dahil) aynen uygulanacak.

---

## `RouterError` eklendi — ham `OSError` kullanıcıya sızmasın diye

**Karar:** Router çıktı dizini oluşturamazsa (disk dolu/izin yok) artık ham
bir Python `OSError` değil, tipli `RouterError` fırlatılıyor; CLI bunu
diğer hata tipleriyle aynı temiz mesaj kalıbına çeviriyor.

**Gerekçe:** İlk implementasyonda bu bilinçli olarak "ölümcül" bırakılmıştı
ama tipli hataya sarma adımı atlanmıştı — kod incelemesi sırasında fark
edip düzelttim (bkz. `docs/hatalar_ve_sonuclar.md`). Kullanıcıya sorulmadan,
projenin zaten var olan hata-sarma desenini (`CustodyLedgerError` gibi)
takip ederek doğrudan uygulandı.

---

## Basit çalıştırma arayüzü için `tkinter` seçildi (PySide6/CustomTkinter değil)

**Karar:** `gui/app.py`, stdlib `tkinter` ile yazıldı; chameleon
projesindeki gibi `PySide6`/`customtkinter` kullanılmadı.

**Gerekçe:** Kullanıcı "basit bir arayüz, profesyonel tasarım ilerideki bir
aşamada" dedi. `tkinter` stdlib olduğu için hiçbir bağımlılık eklemiyor —
"şimdilik sade, sonra profesyonelleştir" planına tam uyuyor. Profesyonel
tasarım aşamasına geçildiğinde bu karar yeniden değerlendirilebilir (o
zaman PySide6 gibi bir kütüphane gerekebilir, ama bu YENİ bir karar/onay
gerektirir).

---

## Zamanlanmış görev: bulut rutin değil, yerel Windows Task Scheduler

**Karar:** Gece otomasyonu, Anthropic bulutunda çalışan bir "routine"
yerine, kullanıcının kendi bilgisayarında yerel bir Windows Scheduled Task
olarak kuruldu.

**Gerekçe:** Bulut rutinler projeye erişmek için önce GitHub'a push
gerektiriyor (proje şu an sadece yerel, `git init` yapıldı ama remote yok).
Kullanıcıya iki seçenek (bulut vs. yerel) açıkça sunuldu, kullanıcı yerel
seçeneği seçti — bunun karşılığında bilgisayarın o saatte açık/erişilebilir
olması gerektiği kabul edildi (bkz. aşağıdaki "uyku modu" kararı).

---

## Otomasyon script'i: `--dangerously-skip-permissions` DEĞİL, `--permission-mode auto` + `--permission-prompts none`

**Karar:** Gece 04:00'te çalışacak `claude.exe` çağrısı, tüm güvenlik
kontrollerini atlayan `--dangerously-skip-permissions` yerine
`--permission-mode auto --permission-prompts none` ile yapılandırıldı.

**Gerekçe:** İlk yazdığım script `--dangerously-skip-permissions`
kullanıyordu; bu, Claude Code'un kendi güvenlik sınıflandırıcısı
tarafından REDDEDİLDİ (riskli bulundu). Bunun yerine, bu oturumda zaten
aktif olan "auto mode" (sınıflandırıcı riskli işlemleri otomatik reddeder,
güvenli işlemler otomatik onaylanır) + `--permission-prompts none` (bir
onay gerekseydi bile kimse orada olmadığı için sonsuza dek beklemek yerine
otomatik reddedilir, böylece görev asla "askıda" kalmaz) kombinasyonu
kullanıldı. Bu, hem gözetimsiz çalışmayı mümkün kılıyor hem de tüm güvenlik
ağını devre dışı bırakmıyor.

---

## Zamanlanmış görevde "Bilgisayarı uyandır" (`WakeToRun`) etkinleştirildi

**Karar:** Windows Scheduled Task'a `-WakeToRun` ayarı eklendi.

**Gerekçe:** Kullanıcı sabah 04:00 civarında namazda olacağını, bilgisayarı
o saatte açık bırakamayacağını ama UYKU MODUNDA bırakabileceğini belirtti.
`WakeToRun`, bilgisayar uyku modundaysa (S3) görevi çalıştırmak için onu
uyandırmayı DENER. Bunun çalışması için (a) bilgisayarın fişe takılı
olması gerekiyor (bu makinede pil modunda uyandırma zamanlayıcıları tamamen
kapalı, `powercfg` ile doğrulandı), (b) donanım/BIOS'un RTC uyandırmayı
gerçekten desteklemesi gerekiyor — ikinci koşul benim tarafımdan kesin
garanti edilemez, sadece yazılım tarafı doğru kuruldu.

**Sonuç:** Görev gece hiç çalışmadı (`LastRunTime` "hiç çalışmadı" durumunda
kaldı, log/`SONUC.md` dosyası oluşmadı) — muhtemelen bilgisayar
uyandırılamadı. Kullanıcı sabah yeniden buradayken görev silinip Faz 4 canlı
olarak (bu oturumda) yaptırıldı. Zamanlanmış/gözetimsiz otomasyon fikri
gelecekte tekrar denenebilir ama bu makinenin uyandırma davranışı önce ayrıca
doğrulanmalı.

---

## Hayabusa çağrı sözdizimi gerçek araçla doğrulandı, `csv-timeline` varsayımı yanlış çıktı

**Karar:** Kullanıcının bilgisayarında zaten kurulu bir Hayabusa 1.4.1
bulunduğu öğrenilince, onu (`--help` ile, salt-okunur) doğrudan çalıştırıp
gerçek CLI sözdizimini kontrol ettim ve `detection/catalog/hayabusa_args.yaml`
şablonundaki yanlış `csv-timeline` alt komutunu kaldırdım.

**Gerekçe:** Faz 4 ajanı bu sözdizimini Hayabusa hiç kurulu olmadan tahmin
etmişti (makul ama doğrulanamamış bir varsayımdı). Kullanıcı "bende Hayabusa
zaten vardı" deyince, gerçek `--help` çıktısına bakmak tahminde ısrar
etmekten kesinlikle daha iyi bir seçenekti — 1.4.1 sürümünün hiç alt komut
kullanmadığı (`hayabusa.exe -f dosya [OPTIONS]`), `-f`/`-r`/`-o`/`-q`
bayraklarının doğru olduğu ama `csv-timeline`'ın var olmadığı ortaya çıktı.

**Alternatif (kullanılmadı):** Kullanıcıya sorup onlardan `--help` çıktısını
yapıştırmalarını istemek — daha yavaş olurdu, aracın yolu zaten bulunabildiği
için doğrudan kendim çalıştırmak tercih edildi.

**Yapılamayan kısım:** Gerçek bir `.evtx`'e karşı tam bir tarama (CSV
başlıklarını da doğrulamak için) denendi ama kullanıcının yerel `rules/`
klasörü boş git submodule olduğundan (`git submodule update --init`
çalıştırılmamış) Hayabusa bir Rust panic ile durdu — bu TriageChain'in değil,
kullanıcının yerel kurulumunun eksikliği, bu yüzden düzeltmeye çalışmadım.

---

## Hayabusa'nın eski (1.4.1) kurulumu silinmek yerine, GitHub'dan güncel (4.0.0) sürüm ayrı bir klasöre indirildi

**Karar:** Kullanıcı "şu anki Hayabusa'yı silip [güncelini] kuralım" dedi.
Ben eski klasörü SİLMEDİM — bunun yerine GitHub'ın resmi releases API'siyle
en güncel sürümü (v4.0.0, `hayabusa-4.0.0-win-x64.zip`, 44 MB, gerçek Sigma
kuralları dahil) bulup ayrı, yeni bir klasöre indirip açtım.

**Gerekçe:** Kalıcı dosya silme benim için yasak bir eylem kategorisi
(geri alınamaz veri kaybı riski) — kullanıcı açıkça istese bile bunu ben
yapmıyorum, kullanıcı kendisi yapmalı. Burada silmeye hiç gerek de yoktu:
yeni sürümü ayrı bir klasöre kurup config'i ona işaret ettirmek, eskisini
silmekle AYNI sonucu (güncel, çalışan bir Hayabusa) veriyor, üstelik geri
alınabilir/risksiz.

**Sonuç:** v4.0.0'ın CLI'ı 1.4.1'den TAMAMEN FARKLI çıktı — alt komut
tabanlı (`dfir-timeline`) ve etkileşimli bir sihirbazı var (`-w` ile
kapatılıyor). Bu, "bir sürümde doğrulanan bir varsayım başka bir sürümde
geçersiz olabilir" dersini somutlaştırdı (bkz. `docs/ogrenilenler.md`).
`hayabusa_args.yaml` v4.0.0'a göre güncellendi ve gerçek bir `.evtx`'e karşı
(exit code 0) çalıştığı doğrulandı; CSV başlıkları ise bu sakin makinedeki
loglarda hiç Sigma eşleşmesi olmadığı (0 bulgu) için hâlâ doğrulanamadı.

---

## VSS oluşturma yolu `vssadmin`'den WMI'ye (`Win32_ShadowCopy.Create`) taşındı

**Karar:** Kullanıcının onayıyla gerçek bir Yönetici (UAC) oturumunda canlı
test yapıldığında `vssadmin create shadow`'un bu makinede (ve muhtemelen
güncel Windows istemci sürümlerinde genel olarak) çalışmadığı ortaya çıktı
— komut kendi yardım metninde bile artık listelenmiyor. Golge kopya
OLUŞTURMA kısmı `powershell.exe` üzerinden WMI'nin `Win32_ShadowCopy.Create()`
metodunu çağıracak şekilde değiştirildi; SİLME kısmı (`vssadmin delete
shadows`) değişmedi çünkü o hâlâ çalışıyor (ayrıca doğrulandı).

**Gerekçe:** Faz 1 tasarımı bu komutu, o an gerçek bir Windows makinesinde
test edilemediği için "muhtemelen çalışır" varsayımıyla seçmişti. Gerçek
test bunun yanlış olduğunu gösterince, aynı "pywin32/COM'a gerek yok"
ilkesini koruyan bir alternatif arandı — `powershell.exe` de zaten Windows'a
gömülü, ek bağımlılık getirmiyor.

**Alternatif (kullanılmadı):** `pywin32`'nin VSS COM arayüzünü doğrudan
kullanmak — daha "temiz" olurdu ama ilk günden beri kaçınılan üçüncü parti
bağımlılığı geri getirirdi.

**Sonuç:** Kullanıcının gerçek bilgisayarında, gerçek bir UAC oturumunda
uçtan uca doğrulandı (gölge kopya oluşturuldu, dosya okundu, temizlendi,
kalıntı kalmadı). Bu modül için önceden hiç birim testi yoktu, 7 yeni test
eklendi (toplam 74). Detaylar: `docs/hatalar_ve_sonuclar.md`.

---

## Registry kovanlarına `.LOG1`/`.LOG2` toplama eklendi; router bunları tek başına işlemeyecek şekilde güncellendi

**Karar:** Kullanıcının gerçek laboratuvar verisiyle RECmd test edilirken
"dirty hive" hatası bulununca, `collection/catalog/default_targets.yaml`'daki
4 temel kovan hedefine (`registry_system/sam/security/software`) `.LOG1`/
`.LOG2` glob yolları eklendi; `router/runner.py`'ye de bu uzantıyla biten
dosyaların hiçbir araca gönderilmeden atlanmasını sağlayan bir kontrol
eklendi.

**Gerekçe:** LOG dosyaları hive ile AYNI dizinde olmadan RECmd onları
bulup "replay" edemiyor — bu yüzden aynı hedefin (`target_id`) altında
toplanmaları gerekiyordu (collector, her hedefi kendi alt dizinine
yazıyor). Ama bu, LOG dosyalarının da router tarafından `registry_system`
tipiyle eşleşip BAĞIMSIZ birer RECmd girdisi sanılması riskini doğurdu —
kullanıcıya sormadan, kendi başıma dosya-adı bazlı bir atlama kuralı
ekleyerek çözdüm (mevcut mimariyi bozmayan en küçük değişiklik).

**Alternatif (kullanılmadı):** LOG dosyaları için ayrı bir `target_id`
(`registry_system_logs` gibi) açmak — ama bu, collector'ın "her hedef kendi
alt dizinine yazılır" varsayımıyla çakışırdı (LOG dosyalarının hive ile
AYNI dizinde olması şart), yani ya collector'ı ya da bu deseni değiştirmek
gerekirdi. Mevcut hedefin altına eklemek + router'da atlamak, mimariye
dokunmadan aynı sonucu veriyor.

**Sonuç:** Gerçek bir SYSTEM kovanı + LOG dosyalarıyla RECmd'in artık
çalıştığı doğrulandı. Yeni bir regresyon testi eklendi (toplam 75 test).
Detaylar: `docs/hatalar_ve_sonuclar.md`.

---

## Hayabusa argüman şablonu: `csv-timeline` + doğrulanamadığı açıkça yazıldı

**Karar:** `detection/catalog/hayabusa_args.yaml` şablonu
`csv-timeline -f {input} -r {rules_dir} -o {output_csv} --quiet` olarak
yazıldı ve YAML'in başına bu sözdiziminin bu ortamda **doğrulanamadığı**
uyarısı kondu.

**Gerekçe:** Bu makinede Hayabusa kurulu değil, ağ erişimiyle gerçek CLI
sözdizimini teyit etme imkânı da yoktu. İki seçenek vardı: (a) daha "zengin"
bir komut satırı tahmin etmek (`--no-wizard`, `--ISO-8601`, profil seçimi
gibi bayraklar), (b) yalnızca alt komut + girdi + kural klasörü + çıktı gibi
her sürümde bulunması en muhtemel minimum kümede kalmak. (b) seçildi:
uydurulan her ek bayrak, ilk gerçek çalıştırmada aracın "bilinmeyen argüman"
diyip sıfırdan farklı kodla çıkmasına yol açar. Şablon zaten koda gömülü
olmadığı için (router'daki `tool_mapping.yaml` deseni) düzeltme Python
değiştirmeden yapılabilir.

**Alternatif (kullanılmadı):** Şablonu `runner.py` içine gömmek — daha az
dosya olurdu ama doğrulanmamış bir varsayımı kodun içine saklamak, düzeltmeyi
kullanıcı için "kod değişikliği" haline getirirdi.

---

## Hayabusa'nın CSV başlıkları da kod değil, veri olarak eşlendi

**Karar:** Hayabusa CSV çıktısının sütun adları (`Timestamp`, `RuleTitle`,
`Level`, ...) `Finding` alanlarına, aynı `hayabusa_args.yaml` içindeki
`csv_columns` bloğuyla eşleniyor; her alan için birden fazla aday başlık
denenebiliyor ve karşılaştırma büyük/küçük harf + boşluktan bağımsız.

**Gerekçe:** Argüman şablonuyla tamamen aynı belirsizlik sütun adları için de
geçerli (sürümler arasında `EventID`/`Event ID` gibi farklar olabiliyor).
Eşlemeyi de veri dosyasında tutmak, ilk gerçek çalıştırmada "başlıklar
tanınmadı" uyarısı alındığında düzeltmenin tek bir YAML satırı olmasını
sağlıyor. Ayrıştırma zaten en iyi çaba ilkesiyle yazıldığı için hiçbir aday
tutmasa bile koşu düşmüyor.

---

## Tespit manifestini CLI değil, koşunun kendisi diske yazıyor

**Karar:** `routing_manifest.json`'ı `cli/main.py` yazarken,
`detection_manifest.json`'ı `run_detection()` fonksiyonunun kendisi yazıyor;
CLI yalnızca yolu ekrana basıyor.

**Gerekçe:** İstenen davranış, `detection_completed` custody olayının
manifest dosyasının SHA-256'sını taşıması. Hash, dosya diske yazıldıktan
sonra hesaplanabilir; dolayısıyla yazma işlemi kapanış olayından ÖNCE ve
custody defterine erişimi olan katmanda olmak zorunda. Alternatif (CLI yazsın,
sonra ayrı bir "hash'i deftere işle" çağrısı yapılsın) hem iki adıma
bölünmüş, hem de GUI/başka bir çağıran o ikinci adımı unutursa sessizce
hash'siz kalan bir zincir üretirdi. Bunun bedeli, router ile küçük bir desen
farkı olması — kabul edildi ve `_cmd_detect` içinde yorumla işaretlendi.

---

## Araç kullanılabilirliği koşu başına BİR KEZ kontrol ediliyor (router'da dosya başına)

**Karar:** Router her artefakt için ayrı ayrı "araç konfigüre edilmemiş"
atlaması kaydederken, tespit katmanı bu kontrolü döngüden önce bir kez yapıp
tek bir `detection_skipped` olayı yazıyor (yükünde kaç dosyanın etkilendiği
duruyor).

**Gerekçe:** Router'da her artefakt tipi FARKLI bir araca gidebilir, bu yüzden
atlama kaydı doğal olarak artefakt bazlı. Tespitte ise tüm dosyalar tek bir
araca (Hayabusa) gidiyor: 200 `.evtx` toplanmış bir vakada aynı cümleyi 200
kez deftere yazmak zincire bilgi değil gürültü ekler. Aynı sebeple, `.evtx`
olmayan artefaktlar (prefetch, registry) "atlandı" olarak da kaydedilmiyor —
onlar bu katmanın işi değil, atlanmış sayılmaları yanıltıcı olurdu.

---

## Custody'ye bulgu başına değil, taranan dosya başına tek özet olay yazılıyor

**Karar:** Her Sigma bulgusu için ayrı bir custody olayı yazılmıyor; taranan
her dosya için tek bir `detection_completed_for_artifact` olayı (bulgu sayısı
+ seviyeye göre dağılım) yazılıyor, bulgu detayları yalnızca
`detection_manifest.json`'da duruyor.

**Gerekçe:** Bu, kullanıcının açıkça belirttiği bir istekti; gerekçesi de
şuydu: gözetim zinciri "kim, ne zaman, neyi işledi" sorusunun kanıtıdır,
analiz çıktısının kendisinin deposu değildir. Tek bir `.evtx` binlerce bulgu
üretebilir; bunları zincire yazmak defteri okunamaz hale getirir ve her
doğrulamayı yavaşlatır. Detayların bütünlüğü, manifest dosyasının SHA-256'sı
kapanış olayına işlenerek yine de zincire bağlanıyor.

---

## Rapor katmanı custody defterine YAZMAZ (salt-okunur gözlemci)

**Karar:** `triagechain report`, çalıştığında gözetim zincirine hiçbir olay
eklemiyor; yalnızca manifestleri ve defteri okuyor.

**Gerekçe:** Rapor, zincirin üretim anındaki durumunun fotoğrafıdır. Eğer
rapor üretimi kendi başına bir `report_generated` olayı yazsaydı, raporun
içindeki olay listesi ve `verify_chain` sonucu daha yazıldığı anda eskimiş
olurdu (defterde rapordakinden bir fazla olay bulunurdu) — yani rapor kendi
iddiasını kendi geçersizleştirirdi. Diğer üç katmanın (toplama/yönlendirme/
tespit) deftere yazmasının sebebi delil üzerinde **işlem yapmaları**;
raporlama hiçbir delile dokunmuyor. Bu davranış iki testle kilitlendi
(defterin baytları rapordan önce ve sonra birebir aynı).

**Alternatif (kullanılmadı):** Raporu yazdıktan sonra `report_generated`
olayını (rapor sha256'sı ile) deftere eklemek — "rapor şu an üretildi"
kaydını zincire sokardı ama yukarıdaki tutarsızlığı doğururdu. Raporun
bütünlüğü bunun yerine yanındaki `report.json.sha256` ile korunuyor.

---

## `report.json.sha256`, `sha256sum` ile doğrulanabilir biçimde yazılıyor

**Karar:** Yan dosyanın içeriği çıplak hex özet değil, `<hash>  report.json`
(iki boşluk) satırı.

**Gerekçe:** Bu dosyanın tek amacı raporun **bağımsız** olarak
doğrulanabilmesi. Bu biçimde `sha256sum -c report.json.sha256` (veya Windows'ta
`certutil`/PowerShell ile elle karşılaştırma) hiçbir ek araç yazmadan
çalışıyor. Değerin kendisi yine tam olarak
`hashlib.sha256(report.json içeriği).hexdigest()`.

---

## Rapor kendi kendine yeten bir belge: bulgular rapora kopyalanıyor

**Karar:** `report.json`, tespit bulgularının tamamını (`detection_manifest.json`
ile aynı `Finding` kayıtlarını) kendi içine kopyalıyor; HTML tablosuna ise
yalnızca ilk 500 bulgu yazılıyor.

**Gerekçe:** Rapor çoğu zaman vakadan ayrı, tek başına paylaşılan dosyadır —
başka bir dosyaya bakmadan okunabilmeli. Veri tekrarı bu yüzden bilinçli kabul
edildi. HTML tarafında ise sınır pratik bir zorunluluk: tek bir `.evtx` binlerce
Sigma bulgusu üretebilir, hepsini tabloya basmak tarayıcıda açılamayan bir
sayfa demektir. Sınır aşıldığında HTML bunu açıkça yazıyor ("… bulgunun ilk 500
tanesi gösteriliyor"), tamamı `report.json`'da duruyor — hiçbir veri sessizce
kaybolmuyor.

---

## HTML raporunda gerçek Türkçe karakterler, CLI çıktısında ASCII

**Karar:** `report.html` içindeki metinler tam Türkçe yazılıyor ("GEÇERLİ",
"Yönlendirme henüz çalıştırılmadı"), CLI'nin `print` çıktıları ise projenin
mevcut deseninde ASCII kalıyor ("GECERLI", "Yonlendirme").

**Gerekçe:** HTML her zaman UTF-8 olarak etiketlenip tarayıcıda açılıyor —
orada Türkçe karakterin bozulma riski yok ve rapor insan tarafından okunacak
resmi bir belge. Windows konsolu ise kod sayfasına göre (cp857/cp1254/UTF-8)
farklı davranıyor; mevcut komutların tamamı bu yüzden ASCII yazılmış ve
`report` komutunun tek başına farklı davranması tutarsızlık olurdu.

---

## `report` komutu, zincir geçersizse çıkış kodu 1 döndürüyor

**Karar:** Rapor dosyaları başarıyla yazılmış olsa bile, `verify_chain`
geçersiz derse komut 1 ile çıkıyor (raporun kendisi yine de üretiliyor ve
"GEÇERSİZ" göstergesiyle diske yazılıyor).

**Gerekçe:** `verify-custody` komutu zaten aynısını yapıyor; bir betikte
`triagechain report && ...` yazan kişinin kırık bir zinciri "başarılı" olarak
görmesi kabul edilemez. Kırık zincir raporu üretmeyi engellemiyor — tam tersine
raporun en önemli çıktısı o durumu **göstermek**.

---

## Manifest yolları tek yerde: `resolve_routing_manifest_path` + `resolve_report_path`

**Karar:** `cli/main.py`'nin `_cmd_route`'u içinde inline hesaplanan
`routing_manifest.json` yolu `config/loader.py`'ye taşındı; rapor dosyalarının
yolu için de aynı desende `resolve_report_path` eklendi (HTML ve `.sha256`
yan dosyası bu yoldan türetiliyor).

**Gerekçe:** Diğer üç yol (`manifest.json`, `custody.jsonl`,
`detection_manifest.json`) zaten loader'da tek kaynaktan türetiliyordu; dördüncüsü
CLI'de kalmıştı ve rapor katmanı aynı yolu ikinci kez hesaplamak zorunda
kalacaktı — iki tarafın ayrışması an meselesiydi. Bu, Faz 5'in kapsamı dışında
küçük ama gerekli bir tutarlılık düzeltmesi olarak kullanıcı tarafından da
açıkça istendi.

---

## RECmd'in `--bn` toplu dosyası: kullanıcıdan yol istemek yerine standart bir dosya GÖMÜLDÜ

**Karar:** RECmd'in zorunlu kıldığı `--bn <toplu dosya>` argümanı,
`EricZimmerman/RECmd` deposundaki MIT lisanslı `DFIRBatch.reb` dosyasının
belirli bir sürüme **sabitlenmiş (pinned)** bir kopyası pakete gömülerek
karşılandı (`router/catalog/recmd_batch/DFIRBatch.reb`). Config'de
`router.recmd_batch_file` alanı da eklendi ama bu bir **override**;
boş bırakılırsa gömülü dosya kullanılıyor.

**Gerekçe:** `docs/hatalar_ve_sonuclar.md`'de bu, "kullanıcıdan config'de bir
yol mu istensin, yoksa kendi minimal `.reb`'imizi mi yazalım" şeklinde açık
bir soru olarak duruyordu; üçüncü bir seçenek daha iyi çıktı. (a) Kullanıcıdan
yol istemek, aracın "kutudan çıkar çıkmaz çalışması"nı bozardı — RECmd kurulu
olsa bile toplu dosyanın yolu ayrıca yazılmadan registry hiç ayrıştırılamazdı.
(b) Kendi minimal `.reb`'imizi yazmak, topluluk tarafından bakımı yapılan,
KAPE'nin kendisinin de kullandığı bir standardın yerine bizim uydurduğumuz,
denetlenmemiş ve eksik bir kural setini koymak olurdu — adli bir çıktının
"hangi metodolojiyle üretildiği" sorusuna verilecek en zayıf cevap budur.
(c) Standart dosyayı gömmek ikisinin de sorununu çözüyor: varsayılan hâliyle
çalışıyor, kullanılan kural seti tanınmış/denetlenebilir bir standart, ve
kendi kural setini kullanmak isteyen incelemeci config'den override
edebiliyor.

**Sürüm sabitleme:** RECmd'in kendi `--sync` bayrağı gibi "her koşuda en
güncelini indir" davranışı BİLEREK kullanılmadı — aynı vaka farklı zamanlarda
çalıştırıldığında farklı kural setiyle farklı sonuç üretirdi, bu doğrudan
tekrarlanabilirliği (reproducibility) bozar. Kaynak, sürüm, git commit ve
SHA-256 bilgisi `recmd_batch/PROVENANCE.md`'de duruyor.

**Alternatif (kullanılmadı):** `--bn` yerine RECmd'in kabul ettiği diğer
anahtarlardan biri (`--sa`/`--sk` gibi tekil arama bayrakları) — ama onlar
"belirli bir anahtarı ara" içindir, triaj amaçlı toplu çıkarma yapmaz.

---

## `{batch_file}` yer tutucusuna ARAÇ ADINA göre değil, ŞABLONA göre karar veriliyor

**Karar:** `router/runner.py`, toplu dosyanın gerekip gerekmediğine
`route.tool == "recmd"` diye bakarak değil, rotanın `args` şablonunda
`{batch_file}` yer tutucusunun geçip geçmediğine bakarak karar veriyor.

**Gerekçe:** Yönlendirme eşlemesinin kod değil veri olması bu projenin
kurulu bir deseni (`tool_mapping.yaml`); "hangi araç toplu dosya ister"
bilgisi de o zaman kodda değil, aynı veri dosyasında durmalı. İki yaklaşım
bugün birebir aynı davranıyor (yalnızca RECmd rotalarında bu yer tutucu var,
bir test bunu kilitliyor) ama ileride benzer bir "kural dosyası" isteyen
başka bir araç eklenirse Python'a dokunmak gerekmeyecek. Maliyeti de yok:
tek bir satır, `route.tool == "recmd"` ile aynı uzunlukta.

**Not:** `str.format`'a her rota için `batch_file=` anahtarı veriliyor;
şablonda kullanılmayan bir keyword argümanı Python'da zaten hata üretmez, bu
yüzden diğer araçların şablonları için ayrı bir dal gerekmedi.

---

## Toplu dosyanın varlığı config yüklerken değil, KOŞU anında kontrol ediliyor

**Karar:** `router.recmd_batch_file` pydantic'te yalnızca **mutlak yol**
olduğu için doğrulanıyor (ve yalnızca değer verilmişse — `None` her zaman
geçerli); dosyanın diskte var olup olmadığına router çalışırken bakılıyor ve
yoksa bu ölümcül değil, `processing_skipped` ("RECmd toplu dosyasi
bulunamadi: <yol>") oluyor.

**Gerekçe:** `router.tools` ve `detection.hayabusa_path`/`rules_dir` zaten
tam olarak bu deseni kullanıyor: kullanıcı araçları kurmadan önce
konfigürasyonu yazmış olabilir, config'in kendisi bu yüzden dosya sisteminin
o anki hâline bağlı olmamalı. Ayrıca bir toplu dosyanın bulunamaması tüm
triaj koşusunu düşürmek için çok küçük bir sebep — registry atlanır, MFT ve
olay günlükleri işlenmeye devam eder ve atlamanın **nedeni** deftere yazılır.

---

## Kural seti parmak izi: içerik hash'i değil, YAPI + BOYUT hash'i (bilinçli tradeoff)

**Karar:** `detection_started` custody olayına eklenen
`rules_fingerprint_sha256`, kural klasöründeki dosyaların **içeriklerinden**
değil, `(göreli yol, boyut)` çiftlerinin sıralı listesinden hesaplanıyor
(`rules_file_count` ile birlikte).

**Gerekçe:** Amaç, "bu bulguyu tam olarak hangi kural seti üretti" sorusuna
custody defterinden cevap verebilmek. Router tarafındaki toplu dosya TEK bir
dosya olduğu için doğrudan `hash_file()` ile hash'lenebiliyor, ama Hayabusa'nın
`rules/` klasörü binlerce Sigma kuralı içerir — her koşuda hepsinin içeriğini
okuyup hash'lemek, tespit koşusunun kendisine oranla anlamsız bir maliyet
eklerdi (ve bu maliyet her `.evtx` için değil, koşu başına bir kez bile olsa
kural sayısıyla birlikte büyür).

**Kabul edilen sınırlama:** Dosya EKLENMESİ, ÇIKARILMASI, yeniden
adlandırılması ve BOYUT değişikliği yakalanır; bir kural dosyasının içeriği
**aynı boyutta kalacak şekilde** değiştirilirse bu parmak izi bunu YAKALAMAZ.
Bu, gizlemeye çalışan bir saldırgana karşı bir garanti değil; "kural setim
bu koşudan sonra güncellendi mi / aynı setle mi çalıştım" sorusuna cevap veren
operasyonel bir kayıttır. Sınırlama koda, `docs/chain_of_custody.md`'ye ve bir
testin adına açıkça yazıldı — sessizce "hash var" izlenimi bırakmamak için.

**Alternatif (kullanılmadı):** Tüm kural dosyalarının içeriğini hash'leyip
birleştirmek (Merkle benzeri) — kesin olurdu ama koşu başına binlerce dosya
okuma demekti. İleride gerekirse bu, ayrı ve isteğe bağlı bir "tam parmak izi"
modu olarak eklenebilir; şemayı bozmaz çünkü alan adı zaten
`rules_fingerprint_sha256`.

---

## Yeni custody alanları eklendi, hiçbir mevcut alan değiştirilmedi

**Karar:** `artifact_processed` olayına `recmd_batch_path`/
`recmd_batch_sha256`, `detection_started` olayına `rules_dir`/
`rules_file_count`/`rules_fingerprint_sha256` **eklendi**; iki olayın da
mevcut anahtarlarına dokunulmadı. RECmd dışındaki araçlarda (mftecmd,
evtxecmd, pecmd) toplu dosya alanları hiç yazılmıyor; kural klasörü tanımsız
ya da diskte yoksa parmak izi alanları da hiç yazılmıyor.

**Gerekçe:** Defter geriye dönük uyumlu kalmalı: eski bir vakanın defterini
okuyan bir kod, yeni alanları görmese de çalışabilmeli; yeni bir defteri
okuyan eski bir kod da beklediği alanları bulabilmeli. "Alan var ama değeri
uydurma" (örneğin kural klasörü yokken `rules_file_count: 0` yazmak) bilinçli
olarak seçilmedi — 0 kurallı bir klasörle hiç kontrol edilememiş bir klasör
adli açıdan aynı şey değildir; ikincisinde alanın hiç olmaması, koşunun neden
atlandığını zaten söyleyen `detection_skipped` olayıyla birlikte daha dürüst
bir kayıt oluyor.

---

## Gömülü `.reb` dosyası `pyproject.toml`'da paket verisi olarak listelendi

**Karar:** `[tool.setuptools.package-data]` altındaki
`"triagechain.router.catalog"` girdisi `["*.yaml", "recmd_batch/*.reb",
"recmd_batch/*.md"]` olarak genişletildi.

**Gerekçe:** `recmd_batch/` bir Python paketi değil (içinde `__init__.py`
yok), dolayısıyla `packages.find` onu bulmaz ve varsayılan hâliyle kurulan
pakete `.reb` dosyası HİÇ kopyalanmazdı — geliştirme ağacında (`pip install
-e`) çalışan kod, gerçek bir kurulumda "toplu dosya bulunamadi" diyerek her
registry kovanını atlardı. Katalog YAML'leri için zaten aynı gerekçeyle
yazılmış bir yorum vardı, aynı desen takip edildi.

---

## VSS artık `pywin32` (WMI COM) ile — kullanıcı onaylı, bilinçli bir bağımlılık istisnası

**Karar:** `collection/vss_snapshot.py`, golge kopyayı `subprocess` +
`powershell.exe` + metin ayrıştırma ile değil, `pywin32`'nin
`win32com.client` modülüyle **doğrudan** WMI çağırarak oluşturuyor
(`Win32_ShadowCopy.Create`) ve siliyor (WMI örneğinin kendi `Delete_()`
metodu). `pyproject.toml`'a `"pywin32>=306; sys_platform == 'win32'"` eklendi;
`parse_create_output`, `_build_create_script` ve `_KV_PATTERN` silindi.

**Bu, kullanıcının AÇIKÇA ONAYLADIĞI bilinçli bir bağımlılık istisnasıdır.**
Yukarıdaki iki eski karar ("VSS erişimi: `pywin32`/COM yerine `vssadmin`
subprocess çağrısı" ve "VSS oluşturma yolu `vssadmin`'den WMI'ye taşındı")
ile çelişmiyor: o kararların dayanağı kullanıcının genel "bağımlılıktan
kaçınalım" tercihiydi ve o tercih projenin geri kalanı için hâlâ geçerli —
kullanıcı `pywin32`'yi SADECE bu tek nokta için, gerekçesini görüp
onaylayarak istisna kıldı.

**Gerekçe:** (1) Metin ayrıştırma kırılganlığı tamamen ortadan kalkıyor —
`powershell.exe`'nin ürettiği `ANAHTAR=deger` satırlarını regex ile okumak
yerine WMI'nin zaten yapılandırılmış nesneleri (`Properties_("ShadowID").Value`)
doğrudan kullanılıyor; ayrıştırılacak bir metin yok, dolayısıyla bozulacak bir
ayrıştırıcı da yok. (2) Golge kopya başına fazladan bir süreç
(`powershell.exe`) başlatmaya gerek kalmıyor — adli bir toplama sırasında
hedef sistemde çalıştırılan program sayısı azalıyor. (3) Kod deseninin
kendisi, kullanıcının gerçek makinesinde, gerçek Yönetici (UAC) yetkisiyle,
kod yazılmadan ÖNCE elle doğrulandı (gerçek gölge kopya oluşturuldu, gerçek
dosya okundu, temizlendi, kalıntı kalmadı) — yani bu sefer varsayımla değil,
doğrulanmış bir desenle başlandı.

**Alternatif (kullanılmadı):** `powershell.exe` + `ANAHTAR=deger` çözümünde
kalmak — sıfır bağımlılık avantajını korurdu ama yukarıdaki iki kırılganlığı
da korurdu; kullanıcı bu tradeoff'u görüp bağımlılığı tercih etti.

**Uygulama detayları:**
- `import win32com.client` modül seviyesinde `try/except ImportError` ile
  sarıldı: pywin32 kurulu olmadığında (CI'daki Linux) modülün KENDİSİ import
  edilebilir kalıyor, hata ancak `VssSnapshot` gerçekten kullanılmaya
  çalışıldığında (`__enter__`) veriliyor.
- `pyproject.toml`'daki platform işaretleyicisi (`sys_platform == 'win32'`)
  ŞART: CI `ubuntu-latest` üzerinde çalışıyor ve pywin32'nin Linux wheel'i yok,
  işaretleyici olmadan `pip install -e .[dev]` orada çökerdi.
- Ham COM istisnaları (`pywintypes.com_error` dâhil) dışarı sızmıyor; geniş bir
  `except Exception` ile yakalanıp `CollectionError`'a sarılıyor — COM
  hatalarının kesin tipini önceden bilmek güç olduğu için bilinçli olarak geniş
  tutuldu.
- `VssSnapshot`'ın PUBLIC arayüzü (`__init__(volume, timeout)`, `translate()`,
  context manager protokolü) hiç değişmedi, bu yüzden `collection/collector.py`
  ve `collection/readers.py`'ye dokunulmadı.
- `timeout` parametresi imzada kaldı ama artık kullanılmıyor (WMI çağrıları
  senkron ve yerel); gerçek bir zaman aşımı mekanizması yok, bu bilinen sınırlama
  koda, `docs/architecture.md`'ye ve roadmap'e yazıldı.
- Testler gerçek pywin32'ye DAYANMIYOR: `sys.modules`'a sahte bir
  `win32com.client` enjekte edilip modül yeniden yükleniyor, böylece aynı
  testler hem bu Windows makinesinde hem de pywin32'siz Linux CI'da çalışıyor
  (pywin32'yi bloke eden bir simülasyonla ayrıca doğrulandı).

---

## Profesyonel arayüz için `PySide6`'ya geçildi; chameleon'un UI kit deseni uyarlandı (kopyalanmadı)

**Karar:** Yeni `src/triagechain/gui_qt/` paketi (`theme.py`, `widgets.py`,
`main_window.py`, `app.py`) `PySide6` ile yazıldı ve `triagechain-gui`
konsol komutu artık bunu açıyor. Eski `tkinter` arayüzü
(`src/triagechain/gui/app.py`) **silinmedi**, sadece komuta bağlı değil.
Mimari desen, kullanıcının chameleon projesindeki
`shared/ui_kit/{theme_qt,widgets}.py` + `launcher/chameleon_gui.py`
üçlüsünden alındı: renk/tipografi/boşluk sabitleri TEK dosyada, bileşenler
(`Card`, `PrimaryButton`, `SecondaryButton`, `Input`, `MonoInput`,
`MonoLabel`, `StatusBadge`, `ProgressBar`) bu sabitlerden türeyen kendi
QSS'lerini kuruyor, ekran ise solda sabit sidebar + sağda `QStackedWidget`.
Kod **kopyalanmadı**; sınıf isimleri/API'si aynı, renk kimliği (yeşil)
TriageChain'e ait.

**Gerekçe:** "Basit çalıştırma arayüzü için `tkinter` seçildi" kararı zaten
"profesyonel tasarım aşamasına geçildiğinde bu karar yeniden
değerlendirilebilir, ama bu YENİ bir karar/onay gerektirir" diyordu — o
aşamaya gelindi ve kullanıcı gerçek, tek pencereli bir masaüstü uygulaması
istedi. Sıfırdan bir tasarım sistemi kurmak yerine, kullanıcının kendi
projesinde zaten olgunlaşmış ve erişilebilirlik denetiminden geçmiş bir
deseni uyarlamak hem daha az kod hem daha az hata demekti.

**Bağımlılık:** `pyproject.toml`'a `PySide6>=6.7` eklendi — `pywin32`'nin
aksine platform işaretleyicisi GEREKMİYOR, PySide6'nın Linux/macOS/Windows
wheel'leri var ve CI (`ubuntu-latest`) üzerinde sorunsuz kuruluyor.

**Alternatif (kullanılmadı):** Mevcut `tkinter` arayüzüne dört butonu daha
eklemek — roadmap'te "karar bekleniyor" olarak duran seçenek buydu. Daha az
iş olurdu ama kullanıcının istediği şey buton sayısı değil, gerçek bir
uygulama hissiydi (sidebar, canlı gösterge kartları, delil zinciri tablosu);
`tkinter` ile bunu tutarlı biçimde yapmak PySide6'dan daha çok, daha
kırılgan kod demekti.

---

## Arayüz kendi iş mantığını YAZMIYOR: var olan fonksiyonları çağırıp diski yeniden okuyor

**Karar:** Dashboard'daki dört aksiyon (`_action_collect/route/detect/report`)
CLI'nin `_cmd_*` fonksiyonlarıyla aynı akışı izliyor ama onların kopyası
değil: doğrudan `run_collection` / `run_router` / `run_detection` /
`build_report`+`write_report` çağrılıyor, yollar `config/loader.py`'nin
`resolve_*` fonksiyonlarından alınıyor. Metrik kartları ve defter tablosu
ise hiçbir sayıyı bellekte tutmuyor — her koşudan sonra `read_snapshot()`
diskteki `manifest.json` / `routing_manifest.json` /
`detection_manifest.json` / `custody.jsonl` dosyalarını **yeniden okuyor**.

**Gerekçe:** Adli bir araçta ekranda görünen sayı ile diskteki delilin
ayrışması kabul edilemez. Arayüz kendi sayacını tutsaydı, dosya dışarıdan
değiştiğinde (ya da bir koşu yarıda kaldığında) ekran gerçeği değil kendi
hafızasını gösterirdi. Diski tek kaynak kabul etmek ayrıca "GUI iş mantığını
duplicate etmesin" kuralını kendiliğinden sağlıyor.

**Sonuç/sınır:** Zincir durumu için `verify_chain` tüm zincire bakıp İLK
kırılmayı bildiriyor; tabloda per-event doğrulama YAPILMIYOR — zincir
geçerliyse tüm satırlar "Doğrulandı", değilse kırılma noktasından
sonrakiler "Şüpheli" gösteriliyor. Defter büyükse yalnızca son 50 olay
tabloya yazılıyor (üstte "toplam N olay, son 50 gösteriliyor" notuyla).

---

## Kontrast hesabı önerilen iki tokeni değiştirdi: `BORDER` düzeltildi, `ACCENT_TEXT` düzeltilmesi GEREKMEDİ

**Karar:** HTML maketinden gelen palet iki noktada ölçülüp güncellendi:
`BORDER` `#454C56` → **`#6A727E`**, `PrimaryButton`'ın yazı rengi ise
chameleon'daki gibi beyaz değil **`BG_DARKEST` (`#0D1117`)**. Buna karşılık
`ACCENT_TEXT` chameleon'daki gibi ayrı/açık bir tona **kaydırılmadı**,
`ACCENT` ile aynı (`#3FB950`) bırakıldı.

**Ölçümler (WCAG 2.1, bu palet üzerinde hesaplandı):**
- `#454C56` / `BG_LAYER2` = **1.82:1** — UI bileşeni sınırı için gereken
  3:1'in çok altında (chameleon'un erişilebilirlik denetiminde öğrendiği
  aynı ders: input alanının nerede başladığı düşük görüşle seçilemiyor).
  `#6A727E` / `BG_LAYER2` = **3.24:1** → geçiyor.
- `ACCENT` (`#3FB950`) / `BG_DARKEST` = **7.45:1**, / `BG_SURFACE` =
  **6.81:1** — küçük metin için AA (4.5:1) zaten fazlasıyla geçiliyor. Yeşil,
  chameleon'un mavisinden (`#2563EB`, `BG_SURFACE`'te 3.35:1) çok daha
  parlak olduğu için ayrı bir "metin tonu" gerekmedi. Token yine de ayrı
  duruyor (kullanım yerleri chameleon'la aynı kalsın diye), sadece değeri
  `ACCENT` ile aynı.
- Beyaz metin / `ACCENT` dolgu = **2.54:1** — okunmuyor. `BG_DARKEST` metin /
  `ACCENT` dolgu = **7.45:1**. Bu yüzden birincil butonun yazısı ve odak
  halkası koyu; chameleon'da beyaz olmasının sebebi orada dolgunun KOYU bir
  mavi olmasıydı, aynı kural farklı renkte ters sonuç veriyor.

**Gerekçe:** Bir tasarım sistemini "uyarlamak", renk değerlerini olduğu gibi
taşımak değil, o sistemin KURALINI (her token kendi zeminine karşı ölçülür)
taşımaktır. Ölçüm yapılmasaydı iki hata da sessizce projeye girecekti.

---

## Tek tema (koyu): `set_mode()`/`get_mode()` ikilisi bilinçli olarak alınmadı

**Karar:** `gui_qt/theme.py` chameleon'un `theme_qt.py`'sinden farklı olarak
tek bir (koyu) palet tutuyor; `DARK`/`LIGHT` sözlükleri, `set_mode()` ve
`get_mode()` yok.

**Gerekçe:** Kullanıcının onayladığı HTML maketi bunu açıkça yazıyordu:
"Kasıtlı olarak tek-tema (koyu) bir kimlik — GitHub/Vercel tarzı geliştirici
araçlarında olduğu gibi bu ürün her zaman koyu temayla açılır." İkinci bir
palet + tema anahtarı eklemek, hiçbir ekranın çağırmadığı ölü bir esneklik
olurdu (projenin "spekülatif kod yazma" kuralı). Açık tema gerçekten
istenirse chameleon'daki `globals().update()` deseni birebir eklenebilir —
bu, kod yapısını değiştirmeyen bir ekleme; dosyanın başına bu not yazıldı.

---

## Metrik/olay ikonları gerçek SVG'den — Unicode glif kullanılmadı

**Karar:** İlk yazılan sürümde metrik kartlarının ikonları (▤/◷/⚠ gibi)
düz Unicode glif karakterleriydi. Bunları, chameleon'un `shared/ui_kit/
icons.py`'sinden birebir uyarlanmış bir `gui_qt/icons.py` yükleyicisiyle
gerçek SVG dosyalarına (`gui_qt/assets/icons/*.svg`, elle çizilmiş, HTML
maketindeki ikonlarla aynı basit stroke şekilleri) çevirdim.

**Gerekçe:** Bu proje chameleon'un TAM OLARAK aynı dersini
(`docs/ogrenilenler.md` → "Qt QListWidgetItem'da emoji yerine SVG ikon
kullan") tekrar keşfetmesin diye — glif/emoji ikonlar headless ya da bazı
ortamlarda kutu (tofu) olarak render olabiliyor, sistemin renkli emoji
fontuna düşme garantisi yok. Ayrıca kullanıcı HTML maketi "referans al, öyle
dursun" dediği için maketin gerçek SVG ikon kullanan görsel dilini burada da
uygulamak doğruydu, sadece renk paleti değil.

**Sonuç:** Aynı fırsatta gözetim zinciri tablosundaki olay hücrelerini de
(düz metin yerine) ikon + kalın olay adı + soluk detay alt satırı şeklinde
HTML maketteki `.event-cell` yapısına uyarlandı; vaka kimliği de artık çıplak
bir etiket değil, kenarlıklı/dolgulu bir "AKTİF VAKA" kutusu (HTML'deki
`.case-pill`). Tablo hücresi artık `QTableWidgetItem` değil özel bir widget
olduğu için, ona bağlı test (`test_gui_qt.py`) da `cellWidget(...).
findChild(QLabel, "event_name")` okuyacak şekilde güncellendi. Tüm paket
(88 test) yeşil.

---

## Metrik kartlarına sparkline + delta metni eklendi — veri UYDURULMADI, gerçek diskten türetildi

**Karar:** Kullanıcı HTML maketi bir ekran görüntüsüyle tekrar gösterip
"görsel olarak birebir bunu istiyorum" dedi — maketteki sparkline'lar ve
delta metinleri ("+18 bu vakada", "2 yüksek önem" gibi) ilk Qt sürümünde
kasıtlı olarak atlanmıştı ("bu turda gerekmiyor, gerçek zaman serisi verisi
yok" gerekçesiyle). Bu istek üzerine `widgets.Sparkline` (QPainter ile
çizilen, alan dolgulu mini çizgi grafiği) eklendi ve üç karta da gerçek
veriden türetilmiş bir eğri + delta metni bağlandı:

- **Toplanan Dosya Sayısı**: eğri = `manifest.artifacts`'in kendi sırasındaki
  kümülatif sayım (1, 2, 3, ... — gerçekten "N. dosyaya kadar kaç dosya
  toplandı" sorusunun cevabı); delta = hata varsa "N artefakt alınamadı",
  yoksa "tümü doğrulandı".
- **Şüpheli Bulgu Sayısı**: eğri = bulguların keşfedilme sırasındaki kümülatif
  sayımı; delta = `Finding.level` alanı "high"/"critical" olanların sayısı
  ("2 yüksek önem" gibi) — maketteki metnin BİREBİR karşılığı, ama gerçek.
- **İşlem Süresi**: eğri = tamamlanmış her fazın (toplama/yönlendirme/tarama)
  kendi süresi (saniye); delta = hangi fazların bittiği ("toplama+tarama").

**Gerekçe:** `artifact-design` ilkesi ("örnek satırlar her zaman öyle
işaretlenir, kullanıcının kendi verisi gibi asla sunulmaz") ile kullanıcının
"birebir görsel" isteği arasında bir gerilim vardı. Çözüm ikisini de
karşılıyor: görsel dil (sparkline'ın kendisi, delta metninin konumu/rengi)
maketle birebir aynı, ama İÇERİK asla uydurulmadı — her sayı gerçek bir
manifest/bulgu listesinden hesaplanıyor. 2'den az nokta olduğunda (ör. tek
bir bulgu, ya da vaka hiç yüklenmemiş) `Sparkline` sahte bir eğri UYDURMAK
yerine düz, nötr bir çizgi çiziyor — bkz. `Sparkline`'ın kendi docstring'i.

**Alternatif (kullanılmadı):** Maketteki gibi süslü/rastgele örnek eğriler
göstermek — kullanıcının kendi vakasıyla hiçbir ilgisi olmayan sahte veri,
projenin "gerçek veri okunur, hiçbir sayı arayüzde ayrıca uydurulmaz"
ilkesini (bkz. `main_window.py`'nin dosya başı docstring'i) doğrudan ihlal
ederdi.

**Sonuç:** `read_snapshot()`'a üç yeni alan çifti (`*_trend`/`*_delta`)
eklendi, mevcut testlere gerçek sahte-vaka fixture'ından beklenen
değerleri (`[1,2,3]`, `"tümü doğrulandı"`, `[125.0, 60.0]`,
`"toplama+tarama"` vb.) doğrulayan yeni assertion'lar eklendi. Tüm paket
(88 test) yeşil.

---

## Chainsaw: Hayabusa'dan BAĞIMSIZ ikinci bir Sigma motoru, AYNI kural setiyle

**Karar:** Roadmap'in "Hayabusa ile çapraz doğrulama" wishlist maddesi için
gerçek Chainsaw (v2.16.5, WithSecure) BYO-subprocess entegrasyonu eklendi.
Mimari, mevcut Hayabusa (`detection/runner.py`) deseninin BİREBİR aynısı:
YAML katalog (`chainsaw_args.yaml`) argv şablonu tanımlıyor, config'de
`chainsaw_path`/`chainsaw_mapping_file`/`chainsaw_timeout_seconds` alanları
var, `chainsaw-scan` CLI komutu ayrı bir `chainsaw_manifest.json` yazıyor.
En önemli mimari karar: Chainsaw, Hayabusa'nın kendi `chainsaw_rules_dir`'i
DEĞİL, config'deki `detection.rules_dir` alanını AYNEN paylaşıyor — çünkü
amaç "iki motor iki farklı kural setiyle ne buluyor" değil, "iki BAĞIMSIZ
motor AYNI kural setiyle aynı sonuca varıyor mu" sorusunu cevaplamak.
Bu paylaşım sayesinde `detection/correlation.py::correlate_sigma_engines()`
`(source_path, rule_title)` eşitliğini gerçek bir çapraz doğrulama sinyali
olarak kullanabiliyor (bkz. o fonksiyonun docstring'i).

Veri modeli tarafında Chainsaw için YENİ bir şema İCAT EDİLMEDİ: gerçek
Chainsaw JSON çıktısı incelendiğinde (EVTX-ATTACK-SAMPLES + SigmaHQ ile
gerçek bir tarama çalıştırılarak) alanların Hayabusa'nın ürettiği
`Finding`/`DetectionManifest` şemasına birebir oturduğu görüldü — bu yüzden
`reporting/models.py::Report.chainsaw` alanı `Optional[DetectionSummary]`
(Hayabusa'nın `report.detection`'ıyla AYNI tip). Bu sayede rapor katmanında
(`builder.py::_sigma_engine_summary`, `renderer.py::_sigma_engine_section`)
iki motor için tek bir ortak fonksiyon yeterli oldu — kopya kod yazılmadı.

**Gerekçe:** Tek bir Sigma motorunun ("Hayabusa dedi ki...") bulguları
kendi başına ne kadar güvenilir olduğu tartışmalı olabilir (kural yanlış
yapılandırılmış, motor kendi hatası vb.). İki bağımsız motorun AYNI kuralı
AYNI dosyada bulması, tek motora göre çok daha güçlü bir sinyal — adli
bilişimde "çapraz doğrulama" prensibinin doğrudan karşılığı. Chainsaw
Rust'la yazılmış, Hayabusa Rust'la yazılmış ama farklı bir kod tabanı ve
farklı bir Sigma-yorumlayıcı implementasyonu kullanıyor; bu da onları
GERÇEKTEN bağımsız kılıyor (aynı motorun iki kopyası değil).

YARA kural setleri gibi (Yara-Rules/rules, GPLv2) Chainsaw'ın kendi ikili
dosyası ve varsayılan kuralları da REPO'YA VENDOR EDİLMEDİ — proje zaten
"araç dağıtılmaz, sadece kullanıcının kendi mutlak yoluyla çağrılır"
mimarisini (Hayabusa/RECmd örneği) tutarlı şekilde sürdürüyor.

**Doğrulama:** `tests/unit/test_chainsaw_runner.py` (9 test) — sahte JSON
kaydı GERÇEK Chainsaw v2.16.5 çıktısından (EVTX-ATTACK-SAMPLES + SigmaHQ ile
gerçek bir tarama çalıştırılıp) alındı, mock değil. `tests/unit/
test_correlation.py`'ye `correlate_sigma_engines` için 2 test eklendi
(ittifak VE ittifak-SAYILMAZ durumları). `reporting/builder.py` ve
`reporting/renderer.py`'ye Chainsaw özeti + "Motor ittifakı (Hayabusa +
Chainsaw)" HTML bölümü eklendi, `tests/unit/test_report_builder.py`'ye 2
yeni test (`test_chainsaw_present_and_agrees_with_hayabusa`,
`test_chainsaw_without_hayabusa_has_no_engine_agreement`) + mevcut 3 testin
"henüz çalıştırılmadı" sayaç beklentisi Chainsaw'ın yeni boş-durum mesajını
da sayacak şekilde güncellendi. Tüm paket (149 test) yeşil.

---

## Yönetici Raporu risk kuralı Chainsaw'ı ve motor ittifakını da sayıyor

**Karar:** `reporting/executive.py::assess_risk()` artık `report.detection`
(Hayabusa) ile birlikte `report.chainsaw`'ı da tarıyor (high/critical bulgu
sayımı ve toplam bulgu sayımı için `for summary in (detection, chainsaw)`
döngüsü) ve `report.engine_agreements` (Hayabusa+Chainsaw ittifakı) dolu
ise -- `report.correlated_artifacts` (Sigma+YARA korelasyonu) ile AYNI
önem sırasında -- riski doğrudan "Kritik" seviyesine çekiyor.
`build_executive_summary()` da `finding_count`/`high_severity_count`'u iki
motorun toplamı olarak hesaplıyor ve anlatıya (varsa) "N dosyada iki
bağımsız davranışsal tarama motoru aynı kuralı doğruladı" cümlesini
ekliyor; yeni `ExecutiveSummary.engine_agreement_count` alanı eklendi.

**Gerekçe:** Chainsaw entegrasyonu (`##Chainsaw: ...` kararına bkz.)
`report.chainsaw` alanını doldurmaya başladıktan sonra, risk kuralı SADECE
Hayabusa'ya bakmaya devam etseydi -- Chainsaw tek başına (Hayabusa hiç
çalışmamış/hata vermiş bir vakada) yüksek önemde bir bulgu bulsa bile
Yönetici Raporu bunu "Bulgu Yok" gösterirdi. Bu, projenin "rapor gerçek
veriden türer, hiçbir katman göz ardı edilmez" ilkesini ihlal ederdi.
Motor ittifakının Kritik sayılması da tutarlılık için: YARA+Sigma
korelasyonu zaten Kritik sayılıyorken, mimarisi ve gücü aynı olan
Hayabusa+Chainsaw ittifakının daha alt bir seviyede kalması keyfi olurdu.

**Not (bilinçli basitleştirme):** İki motor GERÇEKTEN aynı olayları
bulursa (ki `rules_dir` paylaşımı bunu amaçlıyor) `finding_count` bu
olayları İKİ KERE sayar (biri Hayabusa'dan, biri Chainsaw'dan) -- bu bir
"çift sayım" gibi görünebilir, ama alan zaten "toplam ham bulgu sayısı"
anlamına geliyor (YARA eşleşme sayısı da benzer şekilde Sigma'dan ayrı
sayılıyor, hiçbir yerde tekilleştirme yapılmıyor); asıl risk KARARI zaten
`engine_agreements`/`correlated_artifacts` üzerinden ayrı ve öncelikli
olarak veriliyor, bu sayı sadece betimleyici metinde kullanılıyor.

**Doğrulama:** `tests/unit/test_reporting_executive.py`'ye 4 yeni test
eklendi: motor ittifakı Kritik döndürüyor mu, Chainsaw'ın TEK BAŞINA
bulduğu yüksek/kritik bulgu Yüksek risk veriyor mu, `finding_count`/
`high_severity_count` iki motorun toplamı mı, anlatı ittifakı doğru
cümleyle mi ekliyor. Tüm paket (153 test) yeşil.

---

## Chainsaw arayüze bağlandı: Hayabusa panelinin AYNI Finding şemasını paylaşan bir ikizi

**Karar:** `gui_qt/main_window.py`'ye "Chainsaw Tara" butonu (`_action_
chainsaw_scan`, `_action_yara_scan` ile birebir aynı desen) ve Bulgular
sayfasına "Chainsaw Bulguları" paneli eklendi. `CaseSnapshot`'a
`chainsaw_findings`/`engine_agreements` alanları, `read_snapshot()`'a
`chainsaw_manifest.json` okuma bloğu eklendi. Chainsaw paneli YARA
panelinden kasıtlı olarak FARKLI bir tablo tasarımı KULLANMIYOR: Chainsaw
Hayabusa ile AYNI `Finding` şemasını ürettiği için mevcut `_build_finding_
cell()` hücre oluşturucusu doğrudan yeniden kullanıldı (BULGU/SEVİYE/OLAY
ZAMANI/KAYNAK DOSYA kolonları, Bulgular sayfasındaki ana tabloyla birebir
aynı). Motor ittifakı olan (Hayabusa + Chainsaw aynı kuralı aynı dosyada
bulduğu) satırların kaynak-dosya hücresi vurgulanıyor — YARA panelindeki
"Sigma+YARA korelasyonu" vurgusuyla AYNI görsel dil.

**Gerekçe:** Zaten var olan `_build_finding_cell` / tablo kolon düzenini
Chainsaw için TEKRAR YAZMAK, aynı veriyi iki farklı şekilde render eden
bakımı zor bir kopya kod üretirdi — Chainsaw'ın kendisi de zaten "yeni şema
icat etme, var olanı paylaş" kararıyla (bkz. yukarıdaki "Chainsaw:
Hayabusa'dan BAĞIMSIZ..." kararı) tutarlı.

**Doğrulama:** `tests/unit/test_gui_qt.py`'ye 2 yeni test eklendi
(`test_bulgular_sayfasi_chainsaw_ve_motor_ittifaki`,
`test_bulgular_sayfasi_chainsaw_calismamissa_bos_not_gosterir`) + mevcut 2
teste `chainsaw_button` durumu assertion'ı eklendi. Testler `QT_QPA_
PLATFORM=offscreen` ile gerçek Qt render'ı üzerinden (mock DOM değil)
çalıştırıldı. Tüm paket (155 test) yeşil.

---

## Tüm `docs/` dosyaları Chainsaw-sonrası duruma göre yeniden tarandı ve güncellendi

**Karar:** Kullanıcının "docs dosyalarının tamamını doldur" talimatı
üzerine `architecture.md`, `chain_of_custody.md`, `ozellikler.md`,
`ogrenilenler.md`, `hatalar_ve_sonuclar.md`, `oturum_ozeti.md`,
`sohbet_ozeti.md`, `roadmap.md`, `config_reference.md` ve `config/
triagechain.example.yaml` tek tek okunup güncellendi. Bulunan başlıca
tutarsızlıklar: `architecture.md`'nin VSS bölümü hâlâ "gerçek zaman aşımı
YOK" diyordu (roadmap'te zaten tamamlanmıştı); `chain_of_custody.md`'nin
"Kısıt: tek yazıcı" bölümü hâlâ eski davranışı anlatıyordu (custody
kilidi zaten eklenmişti); `ozellikler.md` YARA/Chainsaw/çoklu disk/gömülü
font/exe'den TEK KELİME bahsetmiyordu (tamamen Faz 5 sonrası donmuş
kalmıştı); `sohbet_ozeti.md` hâlâ "88 test, sadece Dashboard işlevsel"
diyordu.

**Gerekçe:** Bu belgeler ("neden böyle yapıldı" ve "şu an nerede
duruyoruz" sorularının cevabı) yeni bir oturumun ya da başka bir
geliştiricinin kod okumadan güvenip hareket edeceği kaynaklar — eskimiş
bir "bilinen sınırlama" ya da "henüz yapılmadı" notu, ZATEN çözülmüş bir
sorunun tekrar çözülmeye çalışılmasına ya da var olan bir özelliğin
"eksik" sanılmasına yol açabilirdi.

**Doğrulama:** Docs-only değişiklik olduğu için kod tarafı hiç
etkilenmedi; güncelleme sonrası tam paket yine de çalıştırıldı, 155 test
yeşil kaldı.

---

## capa entegrasyonu: yeni bir "supheli dosya" toplama kavramı + YARA'nın şemasını paylaşan bir yetenek analizi

**Karar:** Roadmap'in "capa — PE dosyaları üzerinde otomatik davranış/
yetenek analizi" maddesi için gerçek capa 9.4.0 (Mandiant/FLARE) BYO-
subprocess entegrasyonu eklendi. Bunu yaparken önce bir mimari boşluk
fark edildi: TriageChain'in toplama kataloğu (`default_targets.yaml`)
hiçbir zaman gerçek bir PE/yürütülebilir dosya toplamıyordu (MFT, registry,
event log, prefetch — hiçbiri "bir programın kendisi" değil), ama capa'nın
girdisi tam olarak budur. Bu, kullanıcıya sorulması gereken "çok önemli"
bir karar gibi görünebilirdi, ama kapsamı dar ve geri alınabilir bir
uzantı olduğu (yeni, opsiyonel bir config alanı) ve projenin "roadmap'teki
geliştirmeleri kendi kararlarınla yap" talimatıyla doğrudan örtüştüğü için
kendim karar verdim:

1. **`collection.suspicious_binaries: list[str]`** — analistin ELLE
   gösterdiği şüpheli `.exe`/`.dll` dosyalarının mutlak yolları. Katalogdaki
   diğer hedefler gibi sabit/bilinen bir konum DEĞİL — analistin kendi
   seçtiği, vaka özelinde bir girdi. Tek bir `ResolvedTarget` (`target_id
   ="suspicious_binary"`) altında toplanıyor (VSS gerekmez — `additional_
   volumes`'un aksine, analistin gösterdiği dosya genelde kilitli değildir),
   var olan `_collect_target()` AYNEN yeniden kullanıldı.
2. **`detection/capa_runner.py`** — Hayabusa/Chainsaw/YARA ile AYNI yedi
   güvenlik kuralını izler, ama SADECE `artifact_type_id == "suspicious_
   binary"` olan artefaktları tarar (Hayabusa'nın "sadece event_logs"
   kısıtıyla aynı ilke). Gerçek capa'ya karşı (notepad.exe ile) doğrulandı:
   `-j` JSON çıktısı `{"meta":..., "rules": {<ad>: {"meta": {"namespace":
   ..., "attack": [{"id": "T1129", ...}]}, ...}}}` şeklinde.
3. **Veri modeli**: Finding/DetectionManifest DEĞİL, **YARA'nın YaraMatch/
   YaraManifest şeması yeniden kullanıldı** — capa da (YARA gibi) TEK bir
   dosyaya karşı çalışıp adlandırılmış kural eşleşmeleri üretiyor, olay-
   tabanlı bir zaman/bilgisayar/kanal bağlamı yok. `rule_name` = capa kural
   adı, `tags` = MITRE ATT&CK id'leri (virgülle), `meta` = `namespace=...`.
4. **capa'nın gömülü varsayılan kural seti var** — Hayabusa/Chainsaw/
   YARA'nın aksine `capa_rules_dir` ZORUNLU değil, sadece bir override;
   ayarlanmışsa `-r` argümanı capa_runner.py TARAFINDAN (koşullu olduğu
   için veri değil kod olarak) argv'nin başına eklenir.
5. **Raporlama**: `Report.capa: Optional[YaraSummary]` (YARA ile aynı
   sema), Uzman Raporu'na "capa tarama özeti" bölümü eklendi. **BİLEREK
   risk hesabına (`reporting/executive.py::assess_risk`) hiç katılmıyor**
   ve YARA/Sigma ile bir korelasyon üretmiyor: capa "yetenek" tespit eder,
   "kötü amaçlı davranış" değil — gerçek, zararsız bir notepad.exe'de bile
   35 capa kuralı eşleşti (link function at runtime, check if file exists,
   query registry value gibi tamamen sıradan yetenekler). Bunu YARA/Sigma
   eşleşmesiyle aynı ağırlıkta bir "risk sinyali" saymak yanlış olurdu.

**Gerekçe:** capa'nın kendi belgeleri de bunu açıkça ayırıyor: capa bir
BİNARYNİN NELER YAPABİLECEĞİNİ listeler (statik yetenek envanteri), bir
Sigma/YARA kuralının aksine "bu spesifik örüntü kötü amaçlı" demez. Bu
yüzden capa'yı deterministik risk kuralına dahil etmek, projenin "hiçbir
şey uydurulmaz, risk gerçek sinyallerden türer" ilkesini (bkz. `executive.py`
docstring'i) ihlal ederdi — neredeyse HER gerçek .exe'yi "riskli" gösterip
Yönetici Raporu'nu anlamsızlaştırırdı. capa+YARA arasında bir korelasyon
(aynı şüpheli dosyayı ikisi de işaretlerse) teknik olarak mümkündü ama
BİLEREK EKLENMEDİ: doğru risk ağırlığını (capa'nın "yetenek" sinyali YARA'nın
"imza" sinyaliyle aynı güçte değil) kullanıcı geri bildirimi olmadan
kalibre etmek spekülatif olurdu — projenin "istenmeyen özellik ekleme"
disiplinine uyularak bu açıkça ERTELENDİ (istenirse ileride eklenebilir).

**Doğrulama:** `tests/unit/test_capa_runner.py` (11 test, gerçek capa
9.4.0 JSON çıktısından alınmış `FAKE_JSON_OUTPUT` ile), `tests/
integration/test_suspicious_binary_collection.py` (5 test, gerçek dosya
kopyalama/hash'leme), `tests/unit/test_report_builder.py` ve `tests/unit/
test_reporting_executive.py`'ye capa'nın rapora yansıdığını AMA risk
seviyesini etkilemediğini kilitleyen testler eklendi, `tests/unit/
test_gui_qt.py`'ye 2 yeni GUI testi + buton durumu assertion'ları eklendi.
CLI'ye `capa-scan` komutu eklendi. Tüm paket (175 test) yeşil.

---

## Plaso/log2timeline ERTELENDİ — kullanıcı onayıyla, gerçek doğrulama imkânsız olduğu için

**Karar:** Roadmap'in sıradaki maddesi Plaso/log2timeline (süper zaman
çizelgesi) idi. Önceki dört entegrasyonda (Chainsaw, YARA, capa, ve daha
önce Hayabusa) ısrarla uygulanan yöntem — gerçek bir ikiliyi indirip gerçek
girdiye karşı çalıştırıp GERÇEK çıktı şeklini doğrulamak — burada denendi
ve **gerçekten başarısız oldu**: `pip install plaso` bu ortamda
çalıştırıldı, Plaso'nun native bağımlılıkları (`libewf-python`,
`libfsapfs-python`, `libfvde-python` gibi libyal C uzantıları) derleme
aşamasında "Microsoft Visual C++ 14.0 or greater is required" hatasıyla
başarısız oldu — bu makinede bir C++ derleme araç zinciri yok. Bu, ben
tarafımdan kod yazmadan ÖNCE gerçek bir komutla üretilmiş, taklit
edilmemiş bir kanıt.

Bu noktada kullanıcıya durum (gerçek hata çıktısıyla birlikte) sunuldu ve
üç seçenek verildi: (1) belgelenmiş sözdizimine dayanarak DOĞRULANMAMIŞ
şekilde kodla, (2) şimdilik atla, (3) kullanıcı kendi ortamında kurup
doğrulasın. **Kullanıcı "ileride yapılacak olarak ayarla" dedi** — yani
Plaso ERTELENDİ, roadmap'te "Daha sonra" bölümünde açıkça "bilinçli
olarak ertelendi" notuyla işaretlendi.

**Gerekçe:** Bu kararı kullanıcıya sormak, standart talimatın ("kendi
kararlarını al, sadece çok önemli bir şey varsa sonraya bırak") istisnası
olarak görüldü — çünkü bu, "hangi YAML alanı" gibi rutin bir tasarım
tercihi değildi: Plaso'nun kendisi iki aşamalı bir boru hattı
(`log2timeline.py` → `psort.py`) ve ağır bir native bağımlılık ayak izine
sahip; gerçek makinede doğrulanamayan bir tahminle yazılan kod, projenin
kendi `ogrenilenler.md`'sinde zaten kayıtlı bir dersi ("belgelenmiş bir
CLI davranışı gerçek makinede test edilene kadar kanıtlanmış sayılmaz")
doğrudan çiğnerdi ve önceki dört entegrasyonla TUTARSIZ bir güven
seviyesinde bir kod tabanı bırakırdı. Kullanıcının bunu bilerek kabul
etmesi ya da ertelemesi gerekiyordu.

**Doğrulama:** Hiçbir kod yazılmadı; sadece `roadmap.md`'ye erteleme notu
eklendi. Test sayısı (175) değişmedi.

---

## Uçtan uca güvenlik incelemesi: tam kod tabanı taraması, kritik/yüksek bulgu yok

**Karar:** Roadmap'in aktif çekirdek maddeleri (Plaso hariç, kullanıcı
onayıyla ertelendi) bittiğinde, standart `/security-review` skill'i
çağrıldı ama BAŞARISIZ oldu: skill `git diff origin/HEAD...` üzerinden
çalışıyor, ama bu depoda hiç commit yok (`git log` → "does not have any
commits yet", remote de yok) — diff alınacak bir taban yok. Commit
oluşturmak kendi başıma alacağım bir karar olmadığı için (kullanıcı
"commit'leri kendi zamanında kendisi yapacak" — bkz. `sohbet_ozeti.md`),
bunun yerine bir subagent'a TÜM `src/` ağacının elle, satır satır
güvenlik incelemesini yaptırdım (diff değil, doğrudan kod okuma).

İncelenen alanlar: her `subprocess.run` çağrı yeri (shell=True/argv
listesi/timeout), yol içerme kontrolü (`_contained_source_path` deseninin
TÜM beş runner'da tutarlı uygulanması), `_unique_dest`'in dosya adı
üzerinden path traversal'a açık olup olmadığı, `yaml.safe_load`'un HER
YAML okuma yerinde kullanılması (8 yer), config şemasındaki yol
alanlarının mutlaklık doğrulaması (yeni eklenen `capa_rules_dir`/
`suspicious_binaries`/`chainsaw_mapping_file` dahil), custody defteri hash
zinciri + yeni dosya kilidi kodunun doğruluğu, GUI'de eval/exec ya da CLI'
dan ayrı/daha az güvenli bir kod yolu olup olmadığı, HTML rapor
render'ında HER değerin `_e()` ile kaçışlanması (stored XSS riski),
sabit-kodlanmış sır/kimlik bilgisi taraması, `pyproject.toml` bağımlılık
sabitlemesi, `triagechain_gui.spec` içeriği.

**Sonuç: HİÇBİR onaylanmış (CONFIRMED) kritik/yüksek seviye bulgu yok.**
İki düşük seviyeli/bilgilendirici madde:

1. **Bağımlılık alt sınırları sabitlenmemiş** (`pydantic>=2` vb., üst sınır
   yok, lockfile yok) — hijyen notu, aktif bir açık değil.
2. **`output_dir`/`custody.log_path` mutlak olmak zorunda değil** —
   projenin diğer TÜM yol alanlarının aksine. İncelemenin kendi
   değerlendirmesi: bu KABUL EDİLMİŞ bir tasarım riski, kırık bir erişim
   kontrolü DEĞİL — bu alanı besleyen tek kaynak analistin kendi yazdığı
   güvenilir config dosyası, güven sınırını aşan bir saldırgan girdisi
   değil. **Kod DEĞİŞTİRİLMEDİ** (davranış değişikliği + var olan config
   dosyalarını bozma riski, gerçek bir güvenlik açığı karşılığında
   gerekçesiz olurdu); sadece `config_reference.md`'ye bu bilinçli
   tasarım tercihini açıklayan bir not eklendi.

**Gerekçe:** Proje zaten kendi güvenlik disiplinini (BYO-araç mimarisi,
`shell=True` yasağı, mutlak yol zorunluluğu, path containment,
`safe_load`) baştan itibaren titizlikle uyguluyordu; bu inceleme o
disiplinin YENİ eklenen dört motorda (Chainsaw/YARA/capa + capa'nın yeni
`suspicious_binaries` toplama yolu) da KIRILMADAN sürdüğünü bağımsız
olarak doğruladı.

**Doğrulama:** İnceleme salt-okunur bir denetimdi, hiçbir kod
değiştirilmedi (config_reference.md'deki tek doküman notu hariç). Test
sayısı (175) değişmedi.

---

## Referans tasarımla gerçek ekran görüntüsü karşılaştırması: kritik `QApplication.setStyle("Fusion")` eksikliği bulundu ve düzeltildi

**Karar:** Kullanıcı, Dashboard'un daha önce baz alınan referans ekran
görüntüsünü tekrar gönderip "birebir aynısının tasarlanması için gerekli
olan şeylerin tamamını araştır, eksikleri bul, tasarımı baştan yap"
istedi. Önce `app.py`'nin gerçek kurulum mantığını (Fusion stili YOK,
gömülü fontlar, taban QSS) birebir taklit eden bir offscreen render
script'i yazıp gerçek `TriageChainWindow`'un GERÇEK bir ekran görüntüsünü
aldım (referans görseldeki verilere yakın sahte bir vaka ile — 247 dosya,
CASE-DEMO-014). Bu, "gerekli olan her şeyin araştırılması" adımının
kendisiydi: fontlar (Inter+JetBrains Mono, gömülü), ikon seti (elle
çizilmiş SVG çizgi ikonlar, Lucide/Feather üslubu), renk paleti
(GitHub Primer koyu tema türevi, `#3FB950` yeşil vurgu) ve kart
yarıçapı (14px) zaten ÖNCEKİ bir oturumda referansa göre kurulmuştu —
**hiçbir yeni varlığın indirilmesi gerekmedi**.

Gerçek ekran görüntüsünde bulunan somut fark: tüm aksiyon butonları
(Yönlendir/Tara/YARA Tara/...) ve başlık şeridi BEYAZ/SOLUK bir arka
planla, native Windows buton görünümüyle render oluyordu — koyu tema
tamamen bozulmuştu. Kök neden bulundu: `app.py`, `QApplication` kurulduktan
sonra HİÇBİR ZAMAN `app.setStyle("Fusion")` çağırmıyordu. Windows'un
varsayılan native stili ("windowsvista"/"windows11"), ağır QSS
temalarını (özellikle `QPushButton`in `:disabled`/hover durumlarını)
TUTARSIZ uyguluyor — native "chrome" QSS'in ALTINDAN sızıp koyu temayı
beyaza çeviriyordu. `app.setStyle("Fusion")`'ı `QApplication` kurulduktan
hemen sonra, herhangi bir widget oluşturulmadan ÖNCE eklemek sorunu
TAMAMEN çözdü (önce/sonra ekran görüntüleriyle doğrulandı).

Ayrıca referans görseldeki delta metinlerinin küçük bir "~" (tilde)
öneki taşıdığı fark edildi ("~+18 bu vakada" gibi); bu, SADECE gösterim
katmanına (`_refresh_metrics`) eklendi — `CaseSnapshot`'taki ham
`*_delta` metinleri değişmedi, ilgili 3 test assertion'ı yeni metne göre
güncellendi.

**Bilinçli olarak DEĞİŞTİRİLMEYEN bir fark:** Referans görsel Dashboard'da
HİÇBİR aksiyon butonu göstermiyor (statik bir maket olduğu için buna
ihtiyacı yok) — gerçek uygulamanın toplama/yönlendirme/tarama/rapor
komutlarını tetikleyecek gerçek kontrollere ihtiyacı var. Butonlar
KALDIRILMADI (kaldırmak gerçek bir işlevi yok ederdi); bunun yerine
zaten ikincil/sade bir görsel ağırlıkta (SecondaryButton, ince kenarlık,
dolgusuz) tasarlanmış durumdaydı, bu yeterli görüldü.

Ekran görüntülerinde "TriageChain" ve "CASE-DEMO-014" etiketlerinin
hemen yanında ince bir dikey çizgi de fark edildi; `window.findChildren()`
ile o piksel sütununu kapsayan HİÇBİR widget bulunamadı ve
`app.focusWidget()` ana pencerenin kendisini gösterdi (bir metin imleci
değil) — bu, `QT_QPA_PLATFORM=offscreen` render/`grab()` boru hattına ait
bir test-araç artefaktı olarak değerlendirildi, gerçek pencereli
kullanımda karşılığı olmayan bir şey; kod tarafında bir değişiklik
YAPILMADI.

**Gerekçe:** `Fusion` stili eksikliği, testlerin (`.text()`/`.isEnabled()`
kontrol eder, piksel karşılaştırması yapmaz) YAKALAYAMAYACAĞI türden bir
hataydı — bu yüzden önceki oturumlarda fark edilmemişti. Gerçek bir ekran
görüntüsü almak (offscreen de olsa) bu sınıf hatayı ortaya çıkarmanın TEK
yoluydu; bu da "gerçek makinede/gerçek render'da doğrulanmadan bir şey
kanıtlanmış sayılmaz" ilkesinin (bkz. `ogrenilenler.md`) GUI'ye uygulanmış
hali.

**Doğrulama:** `app.py`, `main_window.py`, `test_gui_qt.py` değişti; tam
paket çalıştırıldı, 175 test yeşil (3 test yeni "~" önekli metne göre
güncellendi). Düzeltme öncesi/sonrası GERÇEK ekran görüntüleriyle görsel
olarak doğrulandı (`.venv`'e yalnızca bu doğrulama için geçici olarak
kurulan `pillow`, projenin bağımlılıklarına EKLENMEDİ — sadece piksel
karşılaştırma aracı olarak scratchpad script'inde kullanıldı).

---

## Birleşik zaman çizelgesi: Plaso'nun yerine, ZATEN üretilen EZ Tools CSV'lerini birleştiren yeni bir dış-bağımlılıksız katman

**Karar:** Plaso/log2timeline gerçekten kurulamadığı için (bkz. roadmap.md
→ "Daha sonra" — `pip install plaso` bu makinede C++ derleme zinciri
eksikliğinden başarısız oldu, kullanıcı onayıyla ertelendi) roadmap'in
"süper zaman çizelgesi" hedefine ULAŞMANIN başka bir yolu arandı: Plaso'yu
YENİDEN KURMAYI denemek yerine, TriageChain'in router katmanının ZATEN
çalıştırdığı dört EZ Tools'un (MFTECmd/RECmd/EvtxECmd/PECmd) CSV
çıktılarını okuyup TEK bir kronolojik listede birleştiren yeni, dış araç
gerektirmeyen bir katman (`reporting/timeline.py`) yazıldı.

Bu dört aracın GERÇEK CSV şemaları önceden hiçbir yerde doğrulanmamıştı
(router.py sadece bu dosyaları OPAK çıktı olarak üretiyordu, içeriğini
hiç okumuyordu). Bu yüzden dördü de (2026.5.0, net9 derlemeleri,
`download.ericzimmermanstools.com`'un resmi manifestinden) indirilip
GERÇEK örnek verilere karşı çalıştırıldı:
- **MFTECmd** → `EricZimmerman/MFT` deposunun kendi test paketindeki
  gerçek küçük bir `$MFT` (643 KB, `MFT.Test/TestFiles/xw/$MFT`).
- **RECmd** → `EricZimmerman/Registry` deposunun kendi test paketindeki
  gerçek `NTUSER.DAT` kovanı (DFIRBatch.reb ile, `--nl` bayrağıyla —
  "dirty hive" kontrolünü atlıyor, bkz. asağıdaki not).
- **EvtxECmd** → `sbousseaden/EVTX-ATTACK-SAMPLES`'daki gerçek
  `UACME_59_Sysmon.evtx`.
- **PECmd** → Plaso'nun KENDİ test paketindeki gerçek bir
  `NOTEPAD.EXE-D8414F97.pf` (ironik ama pratik: Plaso kurulamadı, ama
  onun test verisi GitHub'dan serbestçe indirilebiliyor).

Gerçek çalıştırmalardan çıkan, projenin daha önce bilmediği somut
bulgular: (1) hiçbir arac `--csvf` verilmeden çağrılmadığı için (router.py
zaten öyle) her biri KENDİ zaman-damgalı varsayılan dosya adını
(`<yyyyMMddHHmmss>_<Arac>..._Output.csv`) kullanıyor — bu yüzden
`timeline.py` dosyayı sabit bir adla DEĞİL, glob deseniyle buluyor.
(2) PECmd `--csv` verildiğinde AYRICA kendiliğinden bir
`*_Output_Timeline.csv` (sade `RunTime,ExecutableName`) üretiyor —
`_parse_pecmd` bunu, ana CSV'yi ayrıştırmak yerine DOĞRUDAN okuyor. (3)
RECmd'nin `--nl` bayrağı ("transaction log dosyaları dirty hive'lar için
yok sayılsın") mevcut `docs/hatalar_ve_sonuclar.md`'deki "dirty hive"
notunu TAMAMLIYOR — daha önce sadece "yanında .LOG dosyaları toplanmalı"
deniyordu, şimdi arac tarafında da bir kaçış yolu olduğu biliniyor
(TriageChain'in KENDİ akışı zaten LOG dosyalarını toplayıp yanına
koyduğu için `--nl` router.py'ye eklenmedi, sadece bu doğrulama sırasında
kullanıldı). (4) RECmd'nin CSV'si DEĞER satırı başınadır (bir anahtarın
onlarca değeri aynı `LastWriteTimestamp`'i taşır) — bu yüzden
`_parse_recmd` `(KeyPath, LastWriteTimestamp)` çiftine göre TEKİLLEŞTİRME
yapıyor (gerçek NTUSER.DAT ile doğrulandı: 2.759 değer satırı → 306
benzersiz anahtar-yazma olayı).

MFTECmd için MACB (Modified/Accessed/Changed/Born — dört ayrı $STANDARD_
INFORMATION zaman damgası) deseni Plaso'nun kendi süper-zaman-çizelgesi
yaklaşımıyla AYNI: her dolu zaman damgası AYRI bir olay olarak yayılıyor,
boş olanlar (ör. hiç erişilmemiş dosyaların LastAccess'i) atlanıyor.

**Gerekçe:** Bu, projenin "gerçek makinede/gerçek ikiliyle doğrulanmadan
hiçbir CLI/CSV şeması varsayılmaz" ilkesinin (bkz. `ogrenilenler.md`) bu
oturumdaki BEŞİNCİ uygulanışı (Hayabusa/YARA/Chainsaw/capa'dan sonra) —
ve yine en az bir gerçek bulgu (RECmd'nin `--nl` bayrağı, PECmd'nin ayrı
Timeline CSV'si, dosya adlandırma deseni) önceden BİLİNMEYEN, sadece
gerçek çalıştırmayla ortaya çıkan bir şeydi. Katman KASITLI olarak
`reporting/` altında (yeni bir `timeline/` paketi değil): diğer
reporting/ modülleri gibi salt-okunur, dış program ÇALIŞTIRMAZ, custody
defterine YAZMAZ — router.py'nin ZATEN ürettiği dosyaları okur.

**Kapsam sınırı (bilinçli):** Bu, Plaso'nun ~600 ayrıştırıcısının
YERİNE geçmez — sadece TriageChain'in zaten topladığı/ayrıştırdığı dört
kaynağı (MFT/registry/olay günlüğü/prefetch) birleştirir. Tarayıcı
geçmişi, disk imajı biçimleri, uygulama-özel artefaktlar gibi Plaso'nun
kapsadığı diğer yüzlerce kaynak KAPSAM DIŞI kalır — bu roadmap.md'de
açıkça belirtildi, "Plaso'nun tam yerine geçti" gibi yanlış bir izlenim
BIRAKILMADI.

**Doğrulama:** `tests/unit/test_timeline.py` (7 test, gerçek CSV
sütunlarından türetilmiş fixture'larla — MACB genişletme, RECmd
tekilleştirme, PECmd Timeline CSV önceliği, EvtxECmd MapDescription/
EventId fallback, eksik dosya/bilinmeyen araç için "olumcul değil"
davranışı, çok-araçlı kronolojik sıralama), `reporting/models.py`/
`builder.py`/`renderer.py`'ye entegrasyon + 1 uçtan uca rapor testi
(`test_timeline_is_built_from_real_pecmd_csv_and_rendered_in_html`),
GUI'nin Raporlar sayfasına bir özet satırı (`report_field_timeline`) +
1 test. Tüm paket (183 test) yeşil.

---

## Zaman çizelgesi için ayrı bir sidebar sayfası eklendi (kullanıcı tercihiyle)

**Karar:** Yukarıdaki karardan sonra kullanıcıya "Raporlar sayfasındaki
özet satırı yeter mi, yoksa tam bir sidebar sayfası mı istiyorsunuz"
sorusu soruldu; kullanıcı tam sayfayı seçti. Yedinci bir sidebar sayfası
("Zaman Çizelgesi", `clock` ikonu) eklendi — `_build_timeline_page()` +
`_refresh_timeline()`, custody/bulgular sayfalarıyla AYNI desen (ZAMAN/
KAYNAK/OLAY/AYRINTI kolonlu tablo, `MonoLabel` ile ayrıntı hücresi,
`_fit_rows_to_cell_widgets`). `CaseSnapshot.timeline`, `read_snapshot()`
içinde `routing_manifest.json` zaten okunuyorken (RoutingManifest ayrıştırma
döngüsü) `build_timeline()` çağrılarak dolduruluyor — routing hiç
çalışmamışsa ya da hiçbir araç CSV üretmemişse bos-durum notu gösteriliyor.

**Gerekçe:** HTML rapordaki bölüm 500 olayla sınırlıyken (`HTML_FINDING_
LIMIT`), gerçek bir vakada zaman çizelgesi binlerce olay içerebilir (MFT
tek başına gerçek bir diskte 100.000+ kayıt üretebilir) — GUI'de ayrı bir
sayfa, hem kesme sınırı olmadan TAM listeyi göstermeye hem de ayrı bir
tabloyu (arama/kaydırma) yönetmeye izin veriyor; Raporlar sayfasındaki
özet satırı ise sadece "kaç olay var, HTML'de bak" diyordu.

**Doğrulama:** Gerçek bir ekran görüntüsü alınıp incelendi (MFT MACB
genişlemesi + Prefetch çalıştırma + Registry RunMRU'nun doğru kronolojik
sırada, doğru insan-okur etiketlerle göründüğü doğrulandı — bkz. yukarıdaki
"Fusion" kararındaki AYNI offscreen-render yöntemi). 3 yeni GUI testi
(vaka yüklenmeden, route çalışmamışsa boş-durum, gerçek PECmd verisiyle
dolu). Tüm paket (186 test) yeşil.

---

## Gerçek marka logosu entegre edildi: exe simgesi, pencere ikonu, sidebar, README, rapor başlığı

**Karar:** Kullanıcı kendi ürettirdiği TriageChain logosunu (yatay
dizilim: T/C + parmak izi simgesi + "TriageChain" kelime işareti +
"DIGITAL FORENSIC" alt başlığı, PNG) sağladı ve "yapılabilecek tüm
şeyleri yap" dedi. Kaynak dosyalar `assets/brand/`'a kondu (kaynak/türetme
notu `assets/brand/PROVENANCE.md`'de — diğer `PROVENANCE.md`'lerden farkı,
üçüncü taraf lisansı DEĞİL, "hangi dosya nereden türedi" izi). Şunlar
yapıldı:

1. **Kare simge çıkarma**: Yatay logodan sadece T/C + parmak izi kısmı,
   PowerShell'in yerleşik `System.Drawing`'iyle (hiçbir paket kurulmadan)
   arka plan rengine göre otomatik sınır tespiti + kareye tamamlama ile
   kırpıldı (`triagechain_mark_square.png`).
2. **Windows `.ico`**: Aynı yöntemle (yine `System.Drawing`, ICO
   konteynerinin PNG-gömülü ICONDIR/ICONDIRENTRY formatı ELLE yazıldı —
   .NET'in kendisi `.ico` YAZMIYOR) 16/32/48/64/128/256px içeren
   çok-çözünürlüklü bir `.ico` üretildi
   (`gui_qt/assets/icons/app_icon.ico`).
3. **`triagechain_gui.spec`**: `EXE(...)`'e `icon=` parametresi eklendi —
   artık `.exe`'nin kendisi Windows Gezgini'nde gerçek marka ikonuyla
   görünüyor.
4. **`gui_qt/icons.py::app_icon()`**: yeni bir yardımcı — `QApplication.
   setWindowIcon()` (tüm pencereler + görev çubuğu grubu için varsayılan)
   VE `TriageChainWindow.setWindowIcon()` (pencerenin kendisi için,
   çiftle-güvence) burada kullanılıyor.
5. **Sidebar marka simgesi**: elle çizilmiş "shield" SVG'sinin yerini
   gerçek logo simgesi aldı (`main_window.py::_build_sidebar`) — offscreen
   ekran görüntüsüyle gerçekten göründüğü doğrulandı.
6. **`README.md`**: yatay logo GitHub'daki sayfanın en üstüne eklendi.
7. **`report.html` başlığı**: logo (420×210'a küçültülmüş ayrı bir kopya,
   `reporting/assets/triagechain_logo_report.png`) **base64 gömülü**
   (`data:image/png;base64,...`) olarak ekleniyor — harici bir dosya
   REFERANSI DEĞİL, projenin "rapor tamamen offline açılabilmeli, hiçbir
   harici kaynak yok" kuralını bozmuyor (`_logo_data_uri()`, dosya
   bulunamazsa sessizce atlanır, rapor logosuz ama yine doğru üretilir).

**Gerekçe:** Görsel varlık üretimi (kırpma/`.ico` dönüştürme) için normalde
akla ilk gelen yol (`pillow` kurup Python'da işlemek) kullanıcı tarafından
REDDEDİLDİ (yeni global güvenlik kuralı: sistem komutu/script çalıştırmadan
önce durup açıklama+onay). Bunun üzerine SIFIR paket kurulumu gerektiren
bir alternatife (Windows'un kendi `System.Drawing`'i, PowerShell
üzerinden) geçildi — hem güvenlik kuralına uyuyor hem de projenin "minimum
bağımlılık" ilkesiyle tutarlı (bu iş için Python'a YENİ bir kütüphane
eklenmedi).

**Doğrulama:** Üretilen `.ico` `System.Drawing.Icon` ile YENİDEN
yüklenerek geçerliliği doğrulandı. Sidebar'daki yeni simge gerçek bir
offscreen ekran görüntüsüyle görsel olarak kontrol edildi. `report.html`
için yeni bir test eklendi (`test_collect_route_detect_then_report`'a):
`'class="report-logo" src="data:image/png;base64,' in html`. Tüm paket
(186 test) yeşil.

---

## İçe aktarma modu (`collection.source_root`): canlı sistem yerine önceden toplanmış bir artefakt ağacı

**Karar:** Kullanıcı gerçek bir üniversite ödevinden kalma bir KAPE
toplama arşivi (`final lab some kape analiz.rar`, 3 ayrı makineden —
user/server/domain — gerçek KAPE `--zip` çıktısı) verip "illa o anlık
çıktı almak zorunda değil, alınmış verileri de analiz edebilmesi gerekir"
dedi. TriageChain'in çekirdek varsayımı ("canlı, çalışan bir Windows
sistemine karşı topla") bunu engelliyordu — katalogdaki her hedef
`%SystemDrive%`'a (ya da `registry_ntuser`/`registry_usrclass` için sabit
`C:`'ye) göre çözülüyordu. Çözüm: `collection.source_root` (opsiyonel,
varsayılan `None`) — ayarlanmışsa:

1. `collection/selector.py::expand_pattern()` HER kalıbı (ister
   `%SystemDrive%` ister sabit `C:\Users\*\...`) sürücü harfini çıkarıp
   `source_root` altına yeniden köklendiriyor (`ntpath.splitdrive` +
   segment listesi + `Path(source_root, *segments)`).
2. `collector.py::run_collection()` VSS'i **hiçbir hedef için**
   açmıyor — `_open_snapshot_if_needed()` hiç çağrılmıyor, `_collect_
   target`'e her zaman `snapshot=None` gidiyor. Katalogdaki `requires_
   vss: true` etiketi SİLİNMİYOR (rapor/bulgu tarafında hâlâ anlamlı) ama
   collector davranışı için `snapshot=None` olduğundan `open_source()`
   zaten `read_plain()`'e düşüyor — içe aktarılmış dosyalar kilitli
   olmadığı için bu doğru ve yeterli.
3. `_collect_additional_volumes()` bu modda atlanıyor ("ek birim"
   kavramının tek bir içe aktarılmış makine ağacında karşılığı yok).
4. `case_opened` custody olayına `mode: "import"` ve `source_root`
   yazılıyor — denetim izinde bunun bir CANLI toplama olmadığı, TriageChain'in
   bu dosyaları ne zaman GÖRDÜĞÜ açıkça duruyor (orijinal edinim TriageChain
   dışında, başka bir araçla/zamanla oldu).

**Neden `ntpath.splitdrive` (os.path DEĞİL):** İlk yazımda `os.path.
splitdrive` kullanılmıştı — Windows'ta doğru çalışıyor ama CI Linux'ta
(`ubuntu-latest`) `posixpath.splitdrive` `"C:"`yi sürücü olarak TANIMIYOR,
rebase mantığı sessizce yanlış sonuç üretirdi (test yazarken bulundu,
gerçek koşum hiç yapılmadan). `ntpath` modülü Windows yol sözdizimini
platformdan BAĞIMSIZ olarak ayrıştırıyor — TriageChain'in katalog yolları
zaten her zaman Windows sözdizimi, hangi platformda TEST edildiği
mantığı değiştirmemeli.

**Gerekçe:** Bu, projenin "canlı toplama" mimarisini KIRMADAN (aynı
katalog, aynı `_collect_target`, aynı hash/custody mantığı yeniden
kullanılıyor, tek bir yeni if/else dalı) gerçek bir kullanıcı ihtiyacını
karşılıyor: DFIR eğitiminde/sınavlarında KAPE ile önceden toplanmış
verinin TriageChain'in kendi tespit/rapor katmanlarından geçirilebilmesi.

**Doğrulama:** GERÇEK bir KAPE zip'i (384 dosya: `$MFT`, SAM/SECURITY/
SYSTEM/SOFTWARE kovanları, 121 gerçek `.evtx`, gerçek prefetch dosyaları)
tam olarak `source_root` ile toplandı: **384/384 dosya, 0 hata**, custody
zinciri geçerli. Ardından `route` adımı GERÇEK MFTECmd/RECmd/EvtxECmd/
PECmd ikilileriyle çalıştırıldı: **376 işlendi, 0 hata** (8 atlanan, hepsi
beklenen — kovan `.LOG1`/`.LOG2` dosyaları tek başına işlenmez). `report`
geçerli bir rapor üretti. 3 yeni entegrasyon testi + 3 yeni birim testi
(`tests/integration/test_import_mode_collection.py`,
`tests/unit/test_selector.py`'ye eklenenler) — VssSnapshot çağrılırsa
patlayan bir mock ile "VSS hiç açılmıyor" iddiası kilitlendi. Tüm paket
(196 test) yeşil.

---

## Windows MAX_PATH (260 karakter) düzeltmesi: `\\?\` uzun-yol öneki

**Karar:** Yukarıdaki gerçek KAPE testinde 5 gerçek `.evtx` dosyası
(uzun Windows olay günlüğü kanal adları, örn.
`Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider%4Operational.evtx`)
+ derin vaka klasör yapısı birleşince hedef yol 260 karakteri aşıp
`FileNotFoundError` verdi — Windows'un klasik `MAX_PATH` sınırı. Bu,
`source_root` özelliğine özgü değil, **projenin var olan, daha önce hiç
fark edilmemiş bir hatasıydı** (canlı toplamada da aynı şekilde
tetiklenebilirdi, sadece o senaryoda hiç bu kadar uzun bir kanal adı +
derin çıktı yolu birlikte denenmemişti). Tek, paylaşılan bir yardımcı
eklendi: `collection/winpath.py::to_long_path()` — Win32 API'nin kendi
`\\?\` (extended-length path) önekini, MUTLAK yollara ekliyor (UNC
yollarını da `\\?\UNC\` ile ayrıca ele alıyor, göreli yollara
DOKUNMUYOR). Bu fonksiyon **BEŞ ayrı dosyada** (aynı `_write_tool_logs`
fonksiyonu projede kasıtlı olarak kopyalanmış durumda, bkz. her birinin
kendi "AYNI adli fonksiyonla birebir ayni kural" notu) TriageChain'in
KENDİ okuduğu/yazdığı yollara uygulandı: `collection/hashing.py::
hash_file`, `collection/readers.py::read_plain`, `collection/collector.py`
(`_copy_and_hash`, `_unique_dest`), `router/runner.py`, `detection/
runner.py`, `detection/yara_runner.py`, `detection/chainsaw_runner.py`,
`detection/capa_runner.py` (her birinin `output_dir.mkdir()` ve
`_write_tool_logs()` çağrıları).

**Bilinçli olarak DOKUNULMAYAN yer:** Dış araçlara (Hayabusa/Chainsaw/
YARA/capa/EZ Tools) subprocess argv'siyle geçen çıktı yolları (`--csv`,
`-o` vb.) `\\?\` ile ÖNEKLENMEDİ — bu yolları o dış ikili kendi I/O'suyla
yazıyor, `\\?\` önekinin o araçlar tarafından nasıl karşılanacağı
DOĞRULANMADI (proje ilkesi: gerçek davranış doğrulanmadan varsayım
yapılmaz). TriageChain sadece KENDİ Python kodunun açtığı dosyalarda
(log dosyaları, hash yeniden-okuma, JSON/CSV geri-okuma) düzeltme yaptı.

**Doğrulama:** Aynı gerçek KAPE toplama testi düzeltmeden SONRA tekrar
çalıştırıldı: **384/384 dosya, 0 hata** (önce 379/384, 5 hata idi).
`tests/unit/test_winpath.py` (4 test, gerçek Windows'ta çalıştırıldı,
`\\?\` önekinin pathlib tarafından beklendiği gibi korunduğu doğrulandı)
eklendi. Tüm paket (196 test) yeşil.

---

## "Yeni Vaka Oluştur" sihirbazı: elle YAML yazma zorunluluğu kaldırıldı

**Karar:** Kullanıcı, kendisine hazır YAML config dosyaları teslim edip
"GUI'de yükle" demem üzerine haklı olarak itiraz etti: "herkes böyle YAML
ile uğraşmaz". İstenen, KAPE'nin kendi GUI'sindeki (gkape) "target source"
+ "target destination" ikilisiyle birebir aynı deneyim — kullanıcı sadece
dosya/klasör seçer, YAML'i hiç görmez. `gui_qt/case_wizard.py` içinde
`NewCaseDialog` eklendi: vaka bilgisi (kimlik/operatör/açıklama), kaynak
(canlı sistem / önceden toplanmış klasör / ZIP — ZIP stdlib `zipfile` ile
otomatik çıkartılıyor, yeni bir bağımlılık eklenmedi), çıktı dizini,
toplanacak artefaktlar (katalogdan otomatik listelenen onay kutuları) ve
opsiyonel bir "araç klasörü" seçtiriyor; "Vakayı Oluştur" tıklanınca bu
seçimlerden geçerli bir `TriageChainConfig` inşa edilip diske YAML olarak
yazılıyor ve hemen `load_config_file()` ile ana pencereye yükleniyor.
Dashboard'a `PrimaryButton("Yeni Vaka Oluştur")` eklendi (mevcut "Vaka
Konfigürasyonu Yükle" — artık ikincil, elle hazırlanmış bir YAML'i açmak
isteyen ileri kullanıcı için hâlâ duruyor).

**Toplu vaka oluşturma (kullanıcının sorusu üzerine eklendi):** Sihirbazın
ilk sürümü tek bir kaynak = tek bir vaka varsayıyordu; kullanıcı haklı
olarak sordu: "bu YAML dosyalarını hep elle mi gireceğiz tek tek, toplu
seçmeye izin vermesi daha iyi olmaz mı". Gerçek KAPE `--zip` çıktısı zaten
TEK bir arşivin kökünde BİRDEN FAZLA makine barındırabiliyor (kullanıcının
kendi test verisi: `<zaman-damgası>_user/`, `..._server/`, `..._domain/`,
her biri kendi `C/` sürücü kökünü taşıyor) — bu yüzden kaynak kök
klasöründe 2+ alt klasör bulunursa (`detect_machine_roots`) sihirbaz
bunları "aday makine" olarak onay kutularıyla listeliyor; işaretlenen her
alt klasör için ayrı bir vaka kimliği (`<temel-kimlik>-<türetilen-ek>`,
zaman damgası atılıp yalnızca rol kısmı kullanılarak, bkz.
`derive_case_suffix`) ve ayrı bir `source_root` (`resolve_drive_root` ile
otomatik olarak alt klasörün kendi `C/` klasörüne indirgeniyor) ile TEK
TIKLAMADA birden fazla YAML üretiliyor. Tek makinelik köklerde (tek alt
klasör, doğrudan `C/`) toplu mod devreye GİRMİYOR — 2. seviye tek bir alt
klasör "birden fazla makine" sayılmaz, aksi halde her normal tek-vaka
kaynağı yanlışlıkla toplu moda düşerdi.

**Araç otomatik bulma:** Kullanıcının kişisel `TriageChain-Tools\` yolu
kod içine GÖMÜLMEDİ (kişisel bir yol, genel amaçlı bir özelliğe uygun
değil) — bunun yerine kullanıcı istediği herhangi bir "araç klasörü"
seçebiliyor, `autodetect_tools()` bu klasör altında bilinen ikili adlarını
(`MFTECmd.exe`, `RECmd.exe`, `EvtxECmd.exe`, `PECmd.exe`, `hayabusa*.exe`,
`yara64.exe`, `chainsaw*.exe`, `capa.exe`) REKÜRSİF arıyor. Hiçbir şey
bulunamaması hata değil — router/detection katmanları zaten tanımsız aracı
"atlandı" olarak ele alıyor (bkz. `config/schema.py`'deki `Optional`
alanlar); sihirbaz sadece kullanıcıyı elle yol yazmaktan kurtarıyor.

**Doğrulama:** Kullanıcının gerçek `final-lab-kape\` kök klasörü (3 gerçek
makine) sihirbaza TEK SEFER verildi — `detect_machine_roots` 3 alt klasörü
doğru buldu, her biri için türetilen `source_root` daha önce elle yazılmış
gerçek config dosyalarındaki (`final_lab_{user,server,domain}.yaml`)
değerlerle BİREBİR eşleşti. Üretilen bir config gerçek `collect` komutuyla
çalıştırıldı: **384/384 dosya, 0 hata** — elle yazılmış config ile aynı
sonuç. `autodetect_tools()` gerçek `TriageChain-Tools\` klasörüne karşı
test edildi: 4 EZ Tools ikilisi + Hayabusa yolu/kural klasörü doğru
bulundu. 18 yeni test eklendi (`tests/unit/test_case_wizard.py`) — saf
yardımcı fonksiyonlar (`derive_case_suffix`, `detect_machine_roots`,
`resolve_drive_root`, `autodetect_tools`) ve Qt sihirbazının tekli/toplu/
canlı-sistem/hata yolları. Tüm paket (214 test) yeşil.

---

## Sihirbaza RAR/7z desteği + iç içe arşiv çözümü (gerçek kullanıcı verisiyle bulundu)

**Karar:** Kullanıcı sihirbazın "ZIP Seç" seçicisiyle kendi gerçek test
verisini (`final lab some kape analiz.rar`) açmaya çalıştı, dosya
görünmedi — sebep basit: dosya `.zip` değil `.rar`. Seçici `*.zip *.rar
*.7z` kabul edecek şekilde genişletildi; `.rar`/`.7z` için makinede kurulu
bir 7-Zip'e (`find_seven_zip()` -- önce bilinen kurulum yolları, sonra
`PATH`) `subprocess` ile devrediliyor (BYO-tool ilkesiyle aynı gerekçe: 7-Zip
gömülmedi, kullanıcı kendi kurduğu sürümü kullanıyor). Bulunamaması hata
değil — `.zip` yolu hiç etkilenmiyor, `.rar`/`.7z` bu durumda açıkça
reddediliyor ("elle çıkartıp Kök Klasör Seç ile seçin").

**İkinci, daha ince bulgu (gerçek `.rar`'ı gerçekten açınca ortaya çıktı):**
Bu `.rar` makineleri KLASÖR olarak değil, doğrudan İÇ İÇE üç ayrı `.zip`
dosyası olarak taşıyordu (`2026-06-07T220139_user.zip` vb. — klasör değil,
dosya). `detect_machine_roots()` sadece klasörlere baktığı için toplu mod
hiç devreye girmiyordu. `_extract_nested_zips()` eklendi: çıkartılan kökte
doğrudan duran `.zip` dosyalarını kendi adlarında alt klasörlere çıkartıp
toplu modun normal akışına (`detect_machine_roots` → onay kutuları) devrediyor.

**Üçüncü bulgu:** Bu iç içe `.zip` dosyalarından biri Python'un stdlib
`zipfile`'ının desteklemediği bir sıkıştırma yöntemi kullanıyordu
(`NotImplementedError: That compression method is not supported`) — ilk
yazımda bu istisna yakalanmıyordu (`except (BadZipFile, OSError)`), sessizce
çökerdi. Çözüm sadece "bir istisna daha yakala" değil, mimari: TÜM arşiv
çıkartma tek bir `extract_archive()` fonksiyonuna toplandı — 7-Zip
kuruluysa `.zip` DAHİL her şey ona devrediliyor (gerçek dünya `.zip`'leri
stdlib'in desteklemediği yöntemler kullanabiliyor, 7-Zip hepsini açabiliyor),
7-Zip yoksa sadece `.zip` için stdlib'e (artık `NotImplementedError` da
yakalanarak) düşülüyor.

**Doğrulama:** Kullanıcının GERÇEK `.rar` dosyasına karşı uçtan uca
çalıştırıldı: 7-Zip ile açıldı → 3 iç içe `.zip` bulundu → her biri kendi
klasörüne çıkartıldı → `detect_machine_roots` 3'ünü de buldu → toplu mod
3 doğru `source_root`'lu config üretti → biri gerçek `collect` ile
çalıştırıldı: **384/384 dosya, 0 hata** (elle hazırlanmış configle birebir
aynı sonuç). 7 yeni test eklendi (`extract_archive` başarı/hata yolları,
`_extract_nested_zips` idempotency dahil). Tüm paket (221 test) yeşil.

---

## Arşiv çıkartma arka plana alındı + ayrı "çıkartma klasörü" butonu

**Karar:** Kullanıcı gerçek kullanımda iki sorun bildirdi: (1) "çıkartılacak
yeri seçtiğimde app çöküyor", (2) "kök dizini ya da rar dosyasını seçtikten
hemen sonra otomatik geliyor çıkartılacak dizin seçme sayfası, anasayfada
onun için bir buton yok". İkisi de aynı kök nedene bağlıydı: `extract_archive`
+ `_extract_nested_zips` bir önceki sürümde ana (GUI) iş parçacığında,
`QFileDialog.getExistingDirectory` diyaloğu kapanır kapanmaz senkron
çalışıyordu — büyük bir arşivde (yüzlerce MB, yüzlerce dosya) Qt'nin olay
döngüsü onlarca saniye bloke oluyor, Windows pencereyi "Yanıt Vermiyor"
işaretliyordu (kullanıcı bunu "çöküyor" olarak yorumladı, haklı olarak).
İkinci şikayet de aynı akışın bir parçası: arşiv seçimiyle hedef seçimi TEK
bir tıklamaya (`_on_pick_source_zip`) zincirlenmişti, kullanıcının kontrol
edebileceği AYRI bir "çıkartma klasörü" adımı/butonu yoktu.

**Çözüm — iki değişiklik:**
1. Tüm çıkartma mantığı (`extract_archive` + `extract_nested_zips`, artık
   modül seviyesinde, Qt widget'ına DOKUNMUYOR) yeni bir `_ExtractionWorker
   (QThread)` içine taşındı; `_start_extraction()` bunu başlatıp
   `succeeded`/`failed` sinyalleriyle sonucu ana iş parçacığına bildiriyor.
   Çalışırken TÜM seçim/onay butonları (Vazgeç dahil — `reject()` override
   edilip iş parçacığı çalışırken engellendi, Esc/pencere X'i de bunu
   tetikliyor) kapatılıyor, `ProgressBar.set_indeterminate()` gösteriliyor.
2. Tek "Arşiv Seç" butonu iki AYRI, numaralı butona bölündü: "1) Arşiv
   Dosyası Seç…" (sadece dosyayı seçer, `_pending_archive_path`'i yazar) ve
   "2) Çıkartma Klasörü Seç…" (ilk buton tıklanana kadar KAPALI, sonra
   etkinleşir) — kullanıcının istediği "onun için bir buton" tam olarak bu.

**Doğrulama:** Kullanıcının gerçek `.rar` dosyasıyla (161MB, 3 iç içe .zip)
`_start_extraction` doğrudan çağrılarak test edildi: iş parçacığı başlar
başlamaz tüm butonlar kapanıyor, ilerleme çubuğu görünüyor; 6,5 saniyede
bitiyor (bu sürede eski senkron sürüm arayüzü tamamen dondururdu);
bitince butonlar/ilerleme çubuğu geri açılıyor, 3 makine doğru tespit
ediliyor. 4 yeni test eklendi (arka plan tamamlanma, hata yolu, çıkartma
sırasında `reject()` engeli, iç içe zip'li tam senaryo — `QThread.wait()` +
`processEvents()` ile senkronize edilerek). Tüm paket (225 test) yeşil.

---

## Sihirbazda "Çıktı Dizini seçemiyoruz" -- gerçek bir yatay taşma hatası

**Karar:** Kullanıcı bir ekran görüntüsüyle "buradan seçemiyoruz" dedi;
görüntüde "Çıktı Dizini" kartında sadece başlık + "Henüz seçilmedi." vardı,
buton görünmüyordu. Kod okuyarak emin olunamadı — bu masaüstü uygulamasını
görsel olarak inceleyecek bir araç yok, bu yüzden `QT_QPA_PLATFORM=offscreen`
altında GERÇEK sihirbaz penceresi kuruldu (embedded font'lar da yüklenerek,
`app.py`'nin gerçek başlatma sırasıyla birebir), `QWidget.grab()` ile PNG'ye
render edilip görsel olarak incelendi -- Qt'nin `grab()`'ı offscreen platform
altında bile gerçek bir pixmap üretebiliyor, bu ekransız bir masaüstü GUI
hatasını GÖREREK doğrulamak için kullanılabilecek genel bir teknik.

**Bulunan kök neden (iki parça):** (1) `_build_targets_card`, 9 artefaktı
2 sütunlu bir `QGridLayout`'a diziyordu; `QCheckBox` metni Qt'de kendiliğinden
satır KIRMAZ, ve katalogdaki açıklamalar (`default_targets.yaml`) uzun --
iki sütun yan yana bu satırları dialog'un sabit genişliğinin (660-700px)
çok üzerine taşırdı. (2) `_build_output_card`/`_build_tools_card`, sonuç
etiketini (`stretch=1`) ve butonu AYNI yatay satırda, etiket ÖNCE buton
SONRA sırayla diziyordu -- paylaşılan `QVBoxLayout` (tüm kartlar aynı
genişliği paylaşır) (1)'deki taşma yüzünden zaten dialog'un görünür
genişliğinden çok daha geniş olunca, etiket stretch=1 ile bu fazla genişliği
kendine alıyor, buton görünür alanın çok ötesine (yatay kaydırma gerektiren
bir bölgeye) itiliyordu. İki hata birbirini besliyordu: (1) olmasa (2) fark
edilmezdi.

**Düzeltme:** `_build_targets_card` tek sütuna çevrildi (9 onay kutusu alt
alta) -- iki widget'ın aynı satırda yan yana durmasından kaynaklanan
genişlik ikiye katlanması ortadan kalktı. `_build_output_card`/
`_build_tools_card`'da buton ve etiket ayrı satırlara ayrıldı (buton
kendi satırında sola yaslı + stretch, etiket ALTTA kendi satırında,
tamamen "Kaynak" kartının zaten doğru çalışan desenine uyumlu) -- böylece
etiketin ne kadar uzun bir yol göstereceği artık butonun konumunu HİÇ
etkilemiyor.

**Doğrulama:** Aynı `grab()` tekniğiyle hem dar (700x700, gerçek varsayılan
boyuta yakın) hem geniş (1400px) pencerede yeniden render edildi -- dar
pencerede artık YATAY kaydırma çubuğu YOK (önceden vardı), "Klasör Seç…"
ve "Araç Klasörü Seç…" butonlarının ikisi de görünür alanda. Tüm paket
(225 test, davranış değişikliği yok, sadece layout) yeşil.

---

## Açık/koyu tema + "Ayarlar" sayfası + çok dil altyapısı eklendi

**Karar:** Kullanıcı iki şey istedi: (1) açık tema, ayrı bir "Ayarlar"
sayfasında olacak şekilde, (2) daha önce ertelenen çok dil desteğinin
durumu. `theme.py` başlangıçta BİLEREK tek (koyu) temayla kurulmuştu --
kendi docstring'i "açık tema gerçekten istenirse chameleon'daki
`globals().update()` deseni birebir buraya eklenebilir" diyordu. Bu
oturumda tam olarak o desen (chameleon'un GERÇEKTEN production'da çalışan
`shared/ui_kit/theme_qt.py` kodu okunarak) birebir uygulandı: `DARK`/`LIGHT`
sözlükleri + `set_mode()`/`get_mode()`, `globals().update()` ile modül
seviyesi renk sabitleri güncelleniyor.

**Açık tema renkleri UYDURULMADI, GERÇEK bir kaynaktan (GitHub Primer'in
yayımlanmış açık tema token'ları) türetildi ve WCAG 2.1 kontrastı gerçek
sRGB relative luminance formülüyle HESAPLANDI** -- projenin koyu temayı da
aynı disiplinle (Primer koyu tema + ölçülmüş kontrast) kurmuş olmasıyla
tutarlı. Bulunan gerçek bir tasarım sorunu: `PrimaryButton` yazı rengi
`t.BG_DARKEST` tokenini kullanıyordu (koyu temada "en koyu renk" anlamına
geliyordu) -- açık temada bu token en AÇIK renge dönüşünce (`#F6F8FA`),
yeşil dolgu üzerinde neredeyse görünmez bir buton yazısı ortaya çıkardı.
Çözüm: chameleon'un aksine (orada ACCENT iki temada da sabit) TriageChain'in
`ACCENT`'i tema başına AYRI (Primer'in success.emphasis/fg ayrımıyla aynı
fikir: koyu `#3FB950`, açık `#1A7F37` -- açık ton koyu temadaki gibi kalırsa
beyaz metin sadece ~2.5:1 verirdi) VE yeni bir `TEXT_ON_ACCENT` tokeni
eklendi (koyu: `#0D1117`, açık: `#FFFFFF`) -- `widgets.py::PrimaryButton`
artık bunu kullanıyor.

**Sayfayı yeniden kurma zorunluluğu:** Widget'lar renkleri KURULUM ANINDA
QSS string'ine gömdüğü için (theme.py'nin kendi, en başından beri var olan
notu), tema değişince zaten var olan widget'lar OTOMATİK değişmiyor.
Chameleon'un `_apply_theme() -> ui.set_mode() + app.setStyleSheet() +
_build_shell() + _show_settings()` deseni birebir kopyalandı:
`TriageChainWindow.__init__` içindeki kabuk kurulumu `_build_shell()`
metoduna çıkarıldı, `_apply_theme(mode)` bunu tema değişince yeniden
çağırıyor. Bir radio butonunun kendi `toggled` sinyali işleyicisi
içinde `_build_shell()`'in O RADİO BUTONUNU DA yok etmesi güvenli mi diye
kontrol edildi: Qt'nin `setCentralWidget()`'ı önceki merkez widget'ı
SENKRON değil `deleteLater()` ile ERTELEYEREK siliyor, bu yüzden hâlâ
çalışmakta olan sinyal işleyicisi güvenle dönüyor -- chameleon'un
production'da AYNI deseni (hiçbir `QTimer.singleShot` savunması olmadan)
kullanması bunu doğruluyor, burada da aynı doğrudan bağlama kullanıldı.

**Çok dil desteği -- kapsam BİLEREK dar tutuldu:** Kullanıcı önce "TR+EN"
onayladı, sonra "TR/EN/DE/FR/ES" (5 dil) istedi, en son "TR/EN/ES/DE/PT/FR"
(Portekizce eklenip bu sırada) + her girdinin "`<KOD> <yerel ad>`"
biçiminde (örn. "EN English") gösterilmesini istedi. Yeni `gui_qt/i18n.py`
bunu chameleon'un `shared/i18n/strings.py` deseniyle (`STRINGS` sözlüğü +
`t(key)`) kurdu, ama TAM çeviri sadece TR+EN için var -- Dashboard/Bulgular/
Raporlar/Vakalar/Toplanan Dosyalar/Delil Zinciri/Zaman Çizelgesi
sayfalarının YÜZLERCE kendi metni ve sidebar navigasyon etiketleri hâlâ
sabit Türkçe (hem görünen etiket hem `main_window.py::SIDEBAR_PAGES`
üzerinden iç dispatch anahtarı olarak kullanılıyor -- ayırmak ayrı, daha
riskli bir refactor gerektiriyor). ES/DE/PT/FR `SUPPORTED_LANGUAGES`'de
SEÇENEK olarak duruyor (kullanıcının istediği 6 dil), ama gerçek çeviri
YOK -- seçilirse `t()` sessizce EN'e düşüyor VE Ayarlar sayfası bunu AÇIKÇA
bir notla ("henüz çevrilmedi") gösteriyor, sessizce yanlış/eksik metin
göstermek yerine. Kullanıcının açık isteği ("kendimiz çevirmeyelim,
literatüre uygun olsun") gereği bu 4 dilin gerçek çevirisi -- adli bilişim
terimlerinin o dildeki gerçek kaynaklara karşı doğrulanması -- ayrı,
büyük bir araştırma+mühendislik aşaması: HENÜZ YAPILMADI, bilerek
ertelendi (küçükten büyüğe: önce çalışan altyapı + iki tam dil, sonra
geri kalan diller).

**Doğrulama:** `QWidget.grab()` ile (offscreen'de bile gerçek bir pixmap
üretiyor) hem koyu hem açık temada Ayarlar sayfası VE Dashboard sayfası
render edilip görsel olarak incelendi -- tema geçişi SADECE Ayarlar
sayfasını değil, TÜM kabuğu (sidebar, kartlar, butonlar, tablolar) doğru
renklerle yeniden çiziyor. 33 yeni test: `test_theme.py` (18 -- mod geçişi,
türetilmiş `ACCENT_TINT`/`RISK_COLORS` yeniden hesaplanması, açık temanın
GERÇEK WCAG kontrastı parametrize testlerle), `test_i18n.py` (9 -- dil
sırası/kapsamı, çevrilmemiş dilin EN'e düşmesi, bilinmeyen anahtarın asla
patlamaması), `test_gui_qt.py`'ye eklenen 6 yeni entegrasyon testi (radio/
combo değişince gerçek pencere durumu, tema geçişinin Dashboard'a da
yansıması, dil acilir listesinin format/sıra doğruluğu). Tüm paket
(258 test) yeşil.

---

## MonoLabel'ın markaya uymayan mavi odak çerçevesi düzeltildi + "Dil / Language" başlığı

**Karar:** Kullanıcı gerçek bir ekran görüntüsüyle "buranın tasarımı çok
sırıtıyor, bağırıyor" dedi -- görüntüde sidebar'daki "AKTİF VAKA" kutusunu
SARAN, markanın yeşil paletiyle hiç uyuşmayan kalın, mavi bir çerçeve
vardı. Kök neden: `MonoLabel` (hash gibi salt-okunur değerlerin klavyeyle
de seçilebilmesi için `FocusPolicy.StrongFocus` alan bileşen) kendi
`:focus` QSS kuralını hiç TANIMLAMIYORDU -- widget klavye odağı alınca
(burada: pencere ilk açıldığında sekme sırasındaki ilk odaklanabilir
widget olduğu için otomatik) Qt/Windows kendi HAM varsayılan odak
dikdörtgenini çiziyordu, ki bu her zaman sistem/Windows mavisi, uygulamanın
kendi paletinden tamamen bağımsız. `Input`/`PrimaryButton` gibi diğer
bileşenler zaten KENDİ `:focus` stillerini tanımlıyordu (bkz. widgets.py),
`MonoLabel` bu adımı hiç atmamıştı -- proje çapında `MonoLabel` kullanılan
HER yerde (sidebar vaka kimliği, wizard'daki yol etiketleri, dashboard'daki
mono değerler) aynı sorun potansiyel olarak vardı.

**Düzeltme:** `MonoLabel`'e `QLabel:focus { border: 1px solid
{t.ACCENT_TEXT}; }` eklendi (dinlenme halinde `border: 1px solid
transparent;` ile aynı boyutu koruyup sıçrama olmadan) -- artık odak
göstergesi markanın kendi yeşiliyle tutarlı, ince bir çerçeve.

**"Dil / Language" başlığı:** Kullanıcının ayrı isteği: dil seçici
kartının başlığı, hangi dil seçili olursa olsun (özellikle henüz
çevrilmemiş bir dile geçilmişse) "Dil" ya da "Language" kelimesini
tanınabilir kılmak için BİLEREK iki dilde birden ("Dil / Language") --
tek bir sabit değer, `i18n.py`'de hem `tr` hem `en` altında aynı.

**Doğrulama:** `QWidget.grab()` ile `case_pill`'e programatik olarak
klavye odağı verilip (`setFocus()`) render edildi -- önceki mavi kutunun
yerini ince yeşil bir çerçeve aldı, görsel olarak doğrulandı. Yeni
`tests/unit/test_widgets.py` (2 test: `MonoLabel` klavyeyle odaklanabilir
kalıyor + kendi stylesheet'inde `QLabel:focus`/`ACCENT_TEXT` kuralını
taşıyor -- regresyon kilidi), `test_i18n.py`'ye 1 yeni test ("Dil /
Language" her iki dilde de aynı). Tüm paket (261 test) yeşil.

---

## Sidebar navigasyonu i18n'e taşındı: dispatch anahtarı ≠ görünen etiket

**Karar:** Kullanıcı "tüm geliştirmelere sırayla başla" dedi -- listedeki
ilk madde (çeviri kapsamının genişletilmesi) için gereken temel adım
buydu. `main_window.py::SIDEBAR_PAGES`/`NAV_ICONS` daha önce hem GÖRÜNEN
Türkçe etiket hem `nav_buttons` sözlük anahtarı hem `_build_sidebar`'daki
dispatch karşılaştırması (`if name == "Toplanan Dosyalar":`) olarak AYNI
string'i kullanıyordu -- `i18n.py`'nin kendi modül başı notunun da
belirttiği gibi bu yüzden "riskli bir refactor" gerektiriyordu. Şimdi
`SIDEBAR_PAGES` SABİT (dile bağlı olmayan) İngilizce kimlikler taşıyor
(`"cases"`, `"custody"`, `"reports"`, `"findings"`, `"files"`,
`"timeline"`, `"settings"`), görünen etiket `i18n.t(f"nav_{id}")`'den
geliyor -- ic dispatch mantığı artık dilden TAMAMEN bağımsız. Sidebar'ın
kendi çerçeve metinleri de (`AKTİF VAKA` pill başlığı, `GENEL` bölüm
etiketi, alt bilgi satırı, başlangıçtaki "Vaka yüklenmedi" yer tutucusu)
`i18n.py`'ye taşındı.

**Kapsam yine bilinçli olarak sınırlı:** sayfaların KENDİ içeriği (Dashboard
metrik kartları, tablo başlıkları, durum mesajları vb.) henüz çevrilmedi --
bu ayrı, sayfa sayfa ilerleyecek bir sonraki adım. Şu an dil değiştirilince
pencere başlığı + sidebar navigasyonu + Ayarlar sayfası İngilizce'ye
geçiyor, geri kalan sayfa içerikleri hâlâ Türkçe.

**Doğrulama:** `QWidget.grab()` ile İngilizce'ye geçilmiş tam pencere
render edilip görsel olarak incelendi -- sidebar'daki yedi etiketin hepsi
("Cases", "Chain of Custody", "Reports", "Findings", "Collected Files",
"Timeline", "Settings") + "ACTIVE CASE"/"GENERAL"/"Chain integrity
monitored" doğru göründü. 1 yeni test eklendi (`test_gui_qt.py`): dil
değişince sidebar etiketleri değişiyor VE İngilizce etiketli butona
tıklamak hâlâ doğru sayfayı açıyor (dispatch bozulmadı). Mevcut testlerdeki
`nav_buttons[...]` referansları yeni İngilizce anahtarlara güncellendi.
Tüm paket (262 test) yeşil.

---

## Dil başlığı: sabit "Dil / Language" yerine aktif dile göre hesaplanan başlık

**Karar:** Bir önceki turda dil kartının başlığı SABİT "Dil / Language"
yapılmıştı (hangi dil seçili olursa olsun aynı). Kullanıcı bunu daha da
netleştirdi: İngilizce'deyken "Dil / Language" yerine SADECE "Language"
(tekrar gereksiz), Portekizce'deyken "Idioma / Language" gibi -- yani
başlık AKTİF DİLDEKİ "dil" kelimesini `Language` ile eşlemeli, statik bir
metin olmamalı. `i18n.py`'ye `_LANGUAGE_WORD_IN_OWN_LANGUAGE` sözlüğü
(tr/en/es/de/pt/fr'nin her birinde "dil" kelimesinin kendi dilindeki
karşılığı) ve bunu `_current_language`'in HAM koduna göre hesaplayan
`language_heading()` fonksiyonu eklendi -- `STRINGS` sözlüğüne konulmadı,
çünkü `t()`'nin "çevrilmemiş dil EN'e düşer" davranışının AKSİNE, bu
başlık çevrilmemiş bir dilde bile o dilin kendi kelimesini göstermeli.

**Doğrulama:** `QWidget.grab()` ile Portekizce ve İngilizce seçiliyken
render edilip görsel olarak doğrulandı -- Portekizce'de "Idioma /
Language", İngilizce'de sadece "Language" (tekrarsız). Eski statik
`settings_language` anahtarı kaldırıldı, testi 6 dilin hepsini kapsayacak
şekilde genişletildi. Tüm paket (262 test) yeşil.

---

## README.md ve CHANGELOG.md güncel duruma getirildi (NVIDIA'ya değil, doğrudan kendim)

**Karar:** README, projenin sadece faz 1-2+4-5'ini (toplama/custody/router/
Hayabusa/rapor) anlatıyordu -- YARA, Chainsaw, capa, birleşik zaman
çizelgesi, PySide6 GUI, "Yeni Vaka Oluştur" sihirbazı, içe aktarma modu,
RAR/7z desteği, açık/koyu tema, çok dil altyapısı gibi bu oturumda (ve
önceki oturumlarda) eklenen HİÇBİR şeyden bahsetmiyordu. Kullanıcının
"NVIDIA'dan yardım alalım" önerisi daha önce bu iş için gündeme gelmişti,
ama kullanıcının kendi NVIDIA yönlendirme kuralı ("ilgili projenin kendi
dosyalarını okuma/yazma... gerektiren isler NVIDIA'ya yönlendirilmemeli")
gereği bu iş -- projenin gerçek güncel durumunu doğru yansıtmak için
`docs/ozellikler.md`/`docs/roadmap.md` okumayı gerektiriyor -- doğrudan
kendim yazıldı, NVIDIA'ya hiç gönderilmedi.

**Kapsam:** README'nin "Kapsam" bölümü sekiz alt bölüme ayrıldı (toplama,
router, dört tespit motoru, birleşik zaman çizelgesi, raporlama, masaüstü
arayüzü); "Kullanım" bölümüne GUI başlatma komutu + `yara-scan`/
`chainsaw-scan`/`capa-scan` CLI komutları eklendi; "Belgeler" bölümüne
`ozellikler.md`/`roadmap.md` linkleri eklendi. `CHANGELOG.md`'ye marka
logosu, içe aktarma modu, MAX_PATH düzeltmesi, sihirbaz (toplu vaka +
RAR/7z dahil), açık/koyu tema + çok dil altyapısı için yeni satırlar
eklendi. GitHub repo açıklaması güncellenmedi -- bu ortamda kimlik
doğrulamalı bir `gh`/API erişimi yok, kullanıcının kendisi güncellemesi
gerekiyor.

---

## Cellebrite'tan iki fikir: Bulgu işaretleme (Tags) + genel arama

**Karar:** Kullanıcıya Cellebrite Physical Analyzer ekran görüntüsü üzerinden
hangi fikirlerin TriageChain'e taşınabileceği soruldu; iki tanesi hem
TriageChain'in kapsamına uyuyordu hem gerçek değer katıyordu (mobil
extraction/Cloud gibi geri kalanı KAPSAM DIŞI bırakıldı, uymuyor):

1. **Bulgu işaretleme (Tags)** -- yeni `gui_qt/tag_store.py`. Bilerek
   gözetim zincirine (custody.jsonl) YAZILMAZ (zincir sadece toplama/
   yönlendirme/tespit OLAYLARINI taşır, analistin sübjektif yorumunu değil)
   ve `*_manifest.json` dosyalarının da PARÇASI DEĞİL (o dosyalar her
   koşuda YENİDEN üretilir, işaretler bir koşudan diğerine KALICI olmalı) --
   ayrı bir `tags.json` (`config/loader.py::resolve_tags_path`). Bir Finding/
   YaraMatch'in kendi ID alanı olmadığı için (bkz. detection/models.py)
   `target_id_for_finding`/`target_id_for_yara_match` KARARLI bir anahtar
   üretiyor (source_path+rule+bağlam alanlarının sha256'sı, ilk 16 hex) --
   aynı bulgu ikinci bir "Tara" koşusundan sonra da AYNI ID'yi alır,
   işaret kaybolmaz. Bulgular sayfasındaki dört tabloya da (Hayabusa/
   Chainsaw/YARA/capa) bir "İŞARET" sütunu eklendi -- tıklayınca işaretsizse
   kısa bir not sorulur (`QInputDialog`, opsiyonel), işaretliyse doğrudan
   kaldırılır.

2. **Genel arama** -- Cellebrite'ın tek arama kutusundan esinlenildi, ama
   TriageChain'in sayfa-tabanlı mimarisine uyacak şekilde UYARLANDI: yeni
   bir çapraz-sayfa sonuç ekranı İCAT EDİLMEDİ, bunun yerine Bulgular/
   Toplanan Dosyalar/Zaman Çizelgesi sayfalarının HER BİRİNE, o sayfanın
   ZATEN yüklü verisini (`self.snapshot`) canlı filtreleyen bir arama kutusu
   eklendi (`QTableWidget.setRowHidden`, satırlar silinmiyor). Bulgular
   sayfasındaki TEK kutu dört tabloyu (Hayabusa/Chainsaw/YARA/capa) BİRDEN
   filtreliyor -- Cellebrite'ın "tek kutu, her şeyi arar" hissine en yakın
   nokta.

**Doğrulama:** `QWidget.grab()` ile gerçek (sahte ama gerçekçi) bulgu
verisiyle render edildi -- işaretli satır dolu yeşil bookmark, işaretsiz
boş kontur ikonuyla görsel olarak ayırt ediliyor; arama kutusuna yazınca
uymayan satırlar gerçekten gizleniyor. 14 yeni test: `test_tag_store.py`
(10 -- kararlı ID üretimi, round-trip, güncelleme, bozuk dosyada
patlamama), `test_gui_qt.py`'ye eklenen 4 (işaretleme UI'si + üç sayfanın
arama filtreleri). Tüm paket (276 test) yeşil.

---

## Oxygen Forensic Detective'ten üç fikir + PDF dışa aktarma

**Karar:** Kullanıcıya Cellebrite'tan sonra Oxygen Forensic Detective'ten
de hangi fikirlerin uygun olduğu soruldu; üçü + kullanıcının ayrıca istediği
PDF dışa aktarma eklendi.

**1. İşaretlenenler özeti** -- bir önceki turda eklenen Tags özelliğinin
doğal devamı: dört tabloya (Hayabusa/Chainsaw/YARA/capa) dağılmış
işaretler artık Bulgular sayfasının EN ÜSTÜNDE tek bir "İşaretlenenler"
kartında toplanıyor. `tags.json` sadece `target_id`+not tuttuğu için
(kaydın kendisini taşımıyor), `_collect_tagged_items()` asıl veriyi
(`self.snapshot`) yeniden tarayıp her kaydın `target_id`'sini hesaplayıp
`self._tags`'te arıyor.

**2. Vaka Notları** -- Dashboard'a eklendi. Tags'in AKSİNE tek bir bulguya
değil VAKANIN GENELİNE ait serbest metin (`gui_qt/case_note_store.py`,
`tags.json` ile AYNI gerekçe: gözetim zincirine yazılmaz, ayrı bir
`case_note.json`). **Bulunan gerçek bir UX riski**: `_refresh()` her
aksiyon bitiminde (toplama/tarama/vb.) çalışıyor -- not kutusunu HER
`_refresh()`'te diskten yeniden yüklemek, kullanıcının o an yazmakta
olduğu kaydedilmemiş metni sessizce silerdi. Çözüm: `_case_note_loaded_for`
(en son hangi `case_id` için diskten yüklendiğini tutar) -- sadece FARKLI
bir vakaya geçilince yeniden yükleniyor, aynı vakada tekrar `_refresh()`
çağrılması metni bozmuyor (test edildi).

**3. CSV dışa aktarma** -- Bulgular (dört kaynağı TEK CSV'de birleştirir),
Toplanan Dosyalar, Zaman Çizelgesi sayfalarına eklendi (`gui_qt/
csv_export.py`, stdlib `csv`, yeni bağımlılık YOK). BİLİNÇLİ tasarım:
sadece EKRANDA GÖRÜNEN (arama filtresinden geçen, `isRowHidden()` ile
kontrol edilen) satırlar yazılır -- "gördüğünü aktar" ilkesi. `utf-8-sig`
(BOM'lu) kullanıldı: BOM olmadan Excel, Türkçe karakterleri (İ/ş/ğ) yanlış
kod sayfasıyla açıyor -- bilinen, gerçek bir Excel davranışı.

**4. PDF dışa aktarma (kullanıcının ek isteği)** -- Raporlar sayfasına
eklendi (`gui_qt/pdf_export.py`). **Yeni bir bağımlılık EKLENMEDİ**:
PySide6 zaten `QtPrintSupport`'u içeriyor -- `QTextDocument.setHtml()` +
`QPrinter(OutputFormat.PdfFormat)` ile gerçek bir PDF üretiliyor, elle
doğrulandı (`%PDF-1.4` imzalı, gerçek bir PDF okuyucuda açılabilir).
`report.html`'in (renderer.py) TAM CSS'ini/JS sekmelerini YENİDEN
ÜRETMEYE çalışmıyor -- `QTextDocument`'in HTML/CSS desteği sınırlı bir alt
küme (flexbox/grid YOK); bunun yerine sade etiketlerle kendi kısa özet
şablonunu çiziyor, tam teknik detay için hâlâ `report.html`'e yönlendiriyor.
**Gerçek, zararsız bir bulgu**: `QT_QPA_PLATFORM=offscreen` ortamında
(sadece testlerde) `document.print_()` çağrısı konsola "Windows fatal
exception: code 0x80040155" (COM `REGDB_E_CLASSNOTREG`) izi basıyor ama
PDF yine de doğru üretiliyor ve test geçiyor -- elle doğrulandı: AYNI kod
`QT_QPA_PLATFORM` ayarlanmadan (gerçek "windows" platformuyla, yani
paketlenmiş uygulamanın GERÇEKTE çalıştığı koşullarda) çalıştırılınca bu
iz HİÇ çıkmıyor. Offscreen eklentisinin, gerçek Windows'un sağladığı bir
yazıcı/font COM kaydını sağlamamasından kaynaklanıyor, Qt bunu içeride
yakalayıp PDF'i yine de doğru üretiyor -- gerçek uygulamayı ETKİLEMİYOR.

**Doğrulama:** `QWidget.grab()` ile Dashboard'daki (kaydedilmiş, zaman
damgalı) Vaka Notları kartı ve Bulgular sayfasındaki İşaretlenenler özeti
görsel olarak doğrulandı. 23 yeni test: `test_csv_export.py` (4),
`test_case_note_store.py` (5), `test_pdf_export.py` (4 -- gerçek PDF
üretimi dahil), `test_gui_qt.py`'ye eklenen 10 (vaka notu kalıcılığı +
kaydedilmemiş-metin-korunması, işaretlenenler özeti, üç CSV export'u
"sadece görüneni yazar" davranışı, PDF export). Tüm paket (299 test) yeşil.

---

## `scripts/system_check.py`: gerçek araçlara/gerçek veriye karşı büyüyen, kalıcı sistem testleri

**Karar:** Bu oturum boyunca "gerçekten çalışıyor mu" diye doğrulamak için
onlarca kez tek seferlik, elle yazılıp atılan `python -c "..."` script'i
kullanıldı (gerçek KAPE toplama, gerçek EZ Tools yönlendirme, sihirbazın
gerçek RAR dosyasıyla davranışı, gerçek PDF üretimi, derlenmiş exe'nin
açılması vb.) -- kullanıcı haklı olarak "her defasında baştan yazmak yerine
tek, büyüyen bir script'te toplayalım" dedi. `scripts/system_check.py`
bunu karşılıyor: her kontrol `check_` ile başlayan bağımsız bir fonksiyon,
script başındaki `_discover_checks()` bunları OTOMATİK bulup listeliyor/
çalıştırıyor -- yeni bir kontrol eklemek için TEK yapılması gereken yeni
bir `check_...()` fonksiyonu yazmak, başka hiçbir yeri değiştirmeye gerek
yok.

**`tests/`'ten BİLİNÇLİ olarak ayrı tutuldu:** `tests/unit/` ve
`tests/integration/` (adına rağmen) CI'da (ubuntu-latest) da çalışır, bu
yüzden gerçek Windows araçlarına (Hayabusa, EZ Tools, 7-Zip) ya da bu
makinedeki gerçek vaka verisine/derlenmiş `.exe`'ye hiç bağımlı OLAMAZ --
hepsi `unittest.mock.patch` ile mock'lanır (kontrol edildi:
`tests/integration/test_end_to_end_detection.py` bile gerçek Hayabusa
çağırmıyor). `system_check.py` TAM TERSİ bir amaca hizmet ediyor --
dosya adı BİLEREK `test_` ile BAŞLAMIYOR (pytest'in yanlışlıkla toplamaması
için), sadece bu Windows geliştirme makinesinde elle çalıştırılıyor.
Gerekli gerçek araç/veri bu makinede yoksa (`SkipCheck`) kontrol
"ATLANDI" olarak işaretleniyor -- sessizce "GEÇTİ" gibi gösterilmiyor.

**Doğrulama:** Sekiz kontrolün hepsi gerçek veriyle çalıştırıldı -- ilk
turda `check_route_real_ez_tools` gerçek bir hata YAKALADI (script'in
kendi kodunda: `RoutingManifest`'in `error_count`/`skipped_count` gibi
alanları olduğunu VARSAYMIŞTIM, gerçekte `errors`/`skipped` listeleri --
`len()` ile düzeltildi). Düzeltmeden sonra sekizi de gerçekten geçti:
gerçek KAPE toplama (384/384), gerçek EZ Tools yönlendirme (0 hata, 8
atlanan), sihirbazın gerçek 3 makinelik KAPE kökünü doğru tespit etmesi,
kullanıcının gerçek `.rar` dosyasının uçtan uca doğru işlenmesi, gerçek
araç klasöründe otomatik bulma, gerçek PDF üretimi, tam pencere açık/koyu
render, ve derlenmiş `.exe`'nin gerçekten açılıp 3 saniye ayakta kalması.

---

## Beşinci tespit motoru: hash listesi (watchlist/IOC) eşleştirme

**Karar:** Kullanıcıya "Cellebrite/Oxygen tükendi, klasik DFIR
araçlarından (X-Ways/EnCase/Autopsy) ne alınabilir" diye soruldu; üç fikir
önerildi, kullanıcı sıralamayı ONAYLADI ve "önce roadmap'e işle, sonra
sırayla yap" dedi. İlk sıradaki: analistin sağladığı bilinen-kötü bir hash
listesiyle toplanan her dosyanın hash'ini karşılaştırmak. Doğal bir uzantı
-- her dosya zaten toplama sırasında hash'leniyor (`CollectedArtifact.
hash_value`), bu yüzden yeni bir dış araca gerek yok.

**Mimari fark (diğer dört motordan):** `detection/watchlist_runner.py`
hiçbir subprocess ÇAĞIRMAZ -- Hayabusa/Chainsaw/YARA/capa'nın hepsi bir
harici ikiliyi (`shell=True` YOK, mutlak yol, zaman aşımı, stdout/stderr
log) sarmalarken, watchlist saf Python sözlük karşılaştırması yapıyor.
Bu yüzden `DetectionConfig.watchlist_hashes_file` BİLEREK bir "araç yolu"
gibi tasarlanmadı (diğerlerindeki `..._path` alanlarının aksine) ve
"tool_unavailable" atlama mantığı sadece "dosya konfigüre edilmemiş/
bulunamıyor" durumunu kapsıyor.

**Reused-schema deseni burada da uygulandı:** capa'nın YARA'nın
`YaraMatch`/`YaraManifest` şemasını yeniden kullanma gerekçesiyle AYNI --
watchlist de (capa gibi) TEK bir dosyaya karşı çalışıp adlandırılmış bir
"kural" (`rule_name = "watchlist:<etiket>"`) eşleşmesi üretiyor, olay
tabanlı bir zaman/bilgisayar/kanal bağlamı yok. Yeni bir dataclass/şema
İCAT EDİLMEDİ.

**Bilinçli mimari sapma -- artefakt başına custody olayı YOK:**
Hayabusa/Chainsaw/YARA/capa'nın hepsi "dosya başına tek özet olay" yazıyor
(`*_completed_for_artifact`) çünkü her biri GERÇEK bir dış araç çağırıyor,
bu da denetlenmesi gereken bir olay. Watchlist'te böyle bir çağrı yok --
binlerce artefaktı saf Python'da karşılaştırmak için ledger'a binlerce
olay yazmak hem gereksiz şişme hem de "hangi olay gerçek bir aracı temsil
ediyor" ayrımını bulanıklaştırırdı. Bunun yerine SADECE
`watchlist_started`/`watchlist_completed` çifti yazılıyor -- sonucun
tamamı zaten `watchlist_manifest.json`'da eksiksiz duruyor.

**Risk hesabına capa'nın TERSİNE katılma kararı:** capa "yetenek" tespit
ettiği için (kötü amaçlı davranış değil, gerçek/zararsız bir `.exe`'de
bile onlarca eşleşme çıkıyor) bilerek risk hesabından HARİÇ tutulmuştu.
Watchlist'in doğası TAMAMEN farklı: bir eşleşme, bilinen-kötü bir hash'e
TAM (byte-birebir) eşleşmedir -- bir Sigma/YARA kuralının sezgisel/
olasılıksal eşleşmesinden farklı olarak pratikte yanlış-pozitif riski
YOKTUR. Bu yüzden `reporting/executive.py::assess_risk()`'e YENİ bir kural
eklendi: ≥1 watchlist eşleşmesi, zincir bütünlüğü kontrolünden HEMEN sonra
(korelasyon/motor ittifakından bile ÖNCE) doğrudan "Kritik" seviyeye
yükseltiyor.

**Diğer entegrasyon noktaları** (capa'nın izlediği AYNI desen tekrarlandı):
`config/loader.py::resolve_watchlist_manifest_path`, CLI `watchlist-check`
komutu, `Report.watchlist` alanı (`YaraSummary`), `reporting/builder.py`,
HTML rapora yeni bölüm (`_watchlist_section`, `_yara_shaped_section`
YENİDEN kullanılarak), GUI'de Dashboard butonu ("Hash Listesi Kontrol Et")
+ Bulgular sayfasında beşinci tablo (ETİKET/HASH ALGORİTMASI/DOSYA/İŞARET
-- `rule_name`'in `"watchlist:"` önekini ve `meta`'nın `hash_algorithm=`
önekini arayüzde SIZDIRMAYAN özel bir render, YARA/capa'nın genel
KURAL/ETİKETLER kolonlarından FARKLI çünkü watchlist'in alan anlamları
farklı).

**Doğrulama:** 13 yeni birim testi (`test_watchlist_runner.py` --
`load_watchlist` ayrıştırma: yorum/boş satır/virgüllü-boşluklu etiket/
büyük-küçük harf duyarsızlık/yinelenen hash son kazanır; `run_watchlist_
check`: konfigüre değil/dosya yok/eşleşme var/eşleşme yok/çoklu artefakt/
ledger olayları/manifest+hash kaydı/CLI). `scripts/system_check.py`'ye
`check_watchlist_matching_real_hash` eklendi -- gerçek KAPE verisini
toplayıp GERÇEK bir toplanan dosyanın GERÇEK hash'ini bir watchlist
dosyasına yazıp eşleştiğini doğruluyor (sahte/mock hash DEĞİL). Tüm paket
(312 test) yeşil; `report.html`'deki "henüz çalıştırılmadı" bölüm
sayısının değişmesiyle ilgili 4 test assertion'ı (yeni beşinci bölüm
eklendiği için) güncellendi.

---

## Rapor kapak sayfası / imza alanı

**Karar:** Kullanıcının onayladığı sıradaki ikinci madde: PDF/HTML rapora,
resmi bir gözetim zinciri belgesi gibi (yazdırılıp elle imzalanabilir)
kullanılabilmesi için basit bir kapak eklendi.

**HTML rapor (`reporting/renderer.py::_cover_section`):** Sekmelerin
(Yönetici/Uzman) DIŞINA, başlığın hemen altına yerleştirildi -- hangi sekme
seçili olursa olsun her zaman görünür, çünkü bir kapak sayfası kavramsal
olarak "içerik" değil, raporun kendisinin kimlik/onay bilgisi. Vaka
kimliği/operatör/açıklama/üretim zamanı/zincir durumu + üç boş imza satırı
içeriyor. `@media print { .cover { page-break-after: always; } }` ile
GERÇEKTEN yazdırıldığında kapak kendi sayfasında kalıyor, geri kalan içerik
ikinci sayfadan başlıyor -- saf CSS, JS yok (raporun "tamamen offline"
ilkesiyle tutarlı).

**PDF dışa aktarma (`gui_qt/pdf_export.py`):** "İmza Alanı" başlıklı bir
tablo, vaka bilgisi tablosunun hemen altına eklendi. `QTextDocument`'in
sınırlı CSS alt kümesi (flexbox/grid YOK, bkz. modülün önceki kararı)
yüzünden HTML raporundaki `.sign-line` (flex tabanlı alt çizgi) DEĞİL,
her satırda `border-bottom` taşıyan bir `<td>` kullanıldı -- aynı görsel
sonucu (boş, imzalanabilir bir çizgi) farklı bir CSS mekanizmasıyla
üretiyor.

**Bilinçli tasarım kararı -- imza satırları BOŞ, bir isim UYDURULMADI:**
`Report.operator` toplama/tarama koşusunu ÇALIŞTIRAN kişi, ama raporu
resmi olarak İNCELEYEN/ONAYLAYAN kişi (örn. bir amir ya da ikinci bir
analist) BAŞKA biri olabilir. Bu ayrımı bilmeden `report.operator`'ı
"İnceleyen" alanına otomatik yazmak yanlış bir imza yerine geçebilirdi --
bu yüzden üç satır (İnceleyen (Ad Soyad) / İmza / Tarih) da elle
doldurulmak üzere BOŞ bırakıldı.

**Doğrulama:** `test_report_builder.py`'ye kapağın vaka bilgisini +
etiketleri içerdiğini VE sekme radyo düğmelerinden ÖNCE geldiğini (HTML
string sırası üzerinden) doğrulayan 1 yeni test; `test_pdf_export.py`'ye
"İmza Alanı" bölümünün ve üç etiketin PDF şablonunda bulunduğunu doğrulayan
1 yeni test. Gerçek PDF üretimi (`scripts/system_check.py::
check_pdf_export_produces_valid_pdf`) yeniden çalıştırılıp `%PDF-` imzalı,
geçerli bir dosya ürettiği teyit edildi. Tüm paket (314 test) yeşil.

---

## Tüm pytest testleri tek dosyada birleştirildi: `tests/test_all.py`

**Karar:** Kullanıcının açık isteği: `tests/unit/` (26 dosya) + `tests/
integration/` (7 dosya), toplam 33 dosya/6854 satır TEK bir dosyada
(`tests/test_all.py`) birleştirildi. Amaç `scripts/system_check.py`'nin
zaten izlediği "tek, büyüyen dosya" felsefesinin pytest paketine de
uygulanması: yeni bir test eklenecekse dosyanın SONUNA eklenir, `pytest`
tek seferde tümünü çalıştırır.

**Mekanik yaklaşım -- neden AST DEĞİL metin tabanlı (regex) dönüşüm:**
33 dosyanın modül-seviyesi isimleri (sabitler, yardımcı fonksiyonlar,
`@pytest.fixture` fonksiyonları, hatta bazı test fonksiyonu adları) birden
fazla dosyada AYNI (`CASE_ID`, `_make_config`, `_ledger`, `config` fixture,
`qt_app` fixture, `test_tool_not_configured_is_skipped` vb. -- 29 çakışan
isim tespit edildi). `ast.unparse()` ile bir AST dönüşümü bu çakışmaları
güvenle çözebilirdi ama TÜM `#` yorum satırlarını SİLERDİ -- bu proje
yorumlara (WHY açıklamalarına) ağırlıklı ölçüde dayanıyor, bu kabul
edilemezdi. Bunun yerine satır-tabanlı regex ile: (1) her dosyadaki
çakışan isimler dosyaya özgü bir önekle yeniden adlandırıldı (`CASE_ID` ->
`CAPA_RUNNER_CASE_ID` gibi, çakışmayanlar OLDUĞU GİBİ bırakıldı --
okunabilirlik için), (2) modül-seviyesi `import` satırları tek bir bloğa
toplanıp metin bazında dedup edildi, (3) her dosyanın baştaki modül
docstring'i `#`-yorum bloğuna çevrildi, (4) her bölüm başına hangi orijinal
dosyadan geldiğini gösteren bir banner yorumu eklendi.

**Bulunan üç gerçek regresyon (mekanik dönüşümün kendi hataları):**
1. Kelime-sınırı (`\bconfig\b`) tabanlı yeniden adlandırma, `triagechain.
   config.loader` gibi modül YOLLARININ içindeki "config" parçasını da
   yanlışlıkla değiştirdi (`.` kelime-sınırı sayıldığı için). **Düzeltme:**
   rename SADECE gövde (import olmayan) satırlarına, satır-satır uygulanıyor
   -- hem modül-seviyesi HEM fonksiyon içi (`from x import y`) import
   satırları TAMAMEN dokunulmadan bırakılıyor.
2. Aynı kelime-sınırı sorunu, `main(["report", "--config", ...])` gibi bir
   CLI bayrağı STRING'inin içindeki "config" kelimesini de değiştirip
   `"--report_builder_config"` gibi geçersiz bir bayrağa dönüştürdü (bir
   testi gerçekten KIRDI, `pytest` ile yakalandı). **Düzeltme:** rename
   deseni `(?<!-)\b...` -- bir tire hemen önce geliyorsa eşleşme YAPILMIYOR.
3. `Path(__file__).resolve().parents[1]` gibi fixture-yolu ifadeleri, dosya
   `tests/unit/` veya `tests/integration/`den `tests/`e TAŞINDIĞI için bir
   dizin derinliği AZALDI -- indeks 1 azaltılmadan bırakılsaydı `fixtures/`
   klasörü yanlış (repo kökü) konuma işaret ederdi. **Düzeltme:** her
   `parents[N]` -> `parents[N-1]` olarak otomatik ayarlandı.

**QT_QPA_PLATFORM sıralama tuzağı (bulundu, ele alındı):** 4 dosya
(`test_gui_qt.py`, `test_pdf_export.py`, `test_case_wizard.py`,
`test_widgets.py`) `os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")`i
KENDİ import'larından ÖNCE çalıştırıyordu (PySide6 import edilmeden önce
ayarlanmalı). Birleştirilmiş dosyada bu satır TEK SEFER, dosyanın EN
BAŞINA (hoisted import bloğundan bile önce) taşındı -- `setdefault`
idempotent olduğu için 4 orijinal çağrının hepsi güvenle kaldırıldı, aynı
etki TEK bir çağrıyla korundu.

**Doğrulama:** Dönüşüm scripti (`scratchpad/merge_tests.py`, tek seferlik,
projeye COMMIT EDİLMEDİ) kendi güvenlik ağlarını içeriyordu: yeniden
adlandırmadan SONRA hâlâ çakışma var mı (yok), import edilen bir isim
FARKLI kaynaklardan mı geliyor (yok). Üretilen dosya `ast.parse()` ile
sözdizimi doğrulandı, SONRA `pytest` ile üç iterasyonda (yukarıdaki üç
regresyon sırayla bulunup düzeltildi) TAM 314/314 yeşile ulaşıldı --
birleştirmeden ÖNCEKİ toplam testle (314) birebir aynı sayı, hiçbir test
sessizce kaybolmadı/atlanmadı. Orijinal 33 dosya `git rm` ile silindi.

---

## ES/DE/PT/FR çevirileri tamamlandı + gerçek bir i18n regresyonu bulundu

**Karar:** Kullanıcının "çevirileri de ekle her dil için ayrıca" isteği
üzerine `i18n.py`'deki `STRINGS` tablosuna ES/DE/PT/FR eklendi.
**Kapsam bilinçli olarak SINIRLI tutuldu**: bu tablo SADECE pencere
başlığı + kenar çubuğu + Ayarlar sayfasını kapsıyor (bkz. modülün kendi
dokstring'i) -- diğer yedi sayfanın (Dashboard, Bulgular vb.) kendi
içeriği main_window.py'de doğrudan Türkçe metin olarak duruyor ve BU
TURDA dokunulmadı; bu, çok daha büyük, ayrı bir aşama olarak kasıtlı
şekilde ertelendi (daha önce de "ayrı bir araştırma aşaması" olarak not
edilmişti).

**Terminoloji:** "Chain of Custody" gibi adli bilişim/hukuk terimleri
için her dilin kendi literatüründe YERLEŞİK karşılıklar kullanıldı,
uydurma çeviri değil: DE "Beweismittelkette", ES "Cadena de Custodia",
PT "Cadeia de Custódia", FR "Chaîne de Possession" (Fransızca'da
"chaîne de custody" gibi İngilizce'den bozma bir kalıp YAYGIN DEĞİL,
Frankofon adli bilişim kaynaklarında "chaîne de possession" kullanılıyor).

**Doğrulama sırasında bulunan gerçek regresyon:** Yeni dilleri görsel
olarak doğrulamak için `QWidget.grab()` ile ES/DE/PT/FR Ayarlar sayfası
ekran görüntüleri alındı (gerçek pencere kurulup dil değiştirilerek).
Almanca ekran görüntüsünde kenar çubuğundaki "AKTİF VAKA" kutusunun ÜST
satırı doğru çevrilmişken ("AKTIVER FALL"), ALT satırı ("Vaka yüklenmedi"
-- vaka yokken gösterilen metin) Türkçe KALDIĞI görüldü. Kök neden:
`main_window.py::_refresh_header()`, `case_pill` widget'ını (ki
sidebar'da olduğu için i18n KAPSAMINDA, ilk kurulumda `i18n.t(
"sidebar_no_case")` ile doğru kuruluyor) `_refresh()` her çağrıldığında
SABİT `"Vaka yüklenmedi"` string'iyle EZİYORDU -- ilk kurulumdaki çeviri
bir sonraki tazelemede kayboluyordu. `i18n.t("sidebar_no_case")` ile
düzeltildi (SADECE bu satır -- aynı fonksiyondaki `case_subtitle`/
`chain_badge`/`load_button` BİLEREK dokunulmadı, onlar Dashboard SAYFA
İÇERİĞİ, i18n kapsamı dışında).

**Doğrulama:** `test_i18n.py` bölümündeki üç test güncellendi
(`test_es_de_pt_fr_henuz_cevrilmedi` → `test_tum_alti_dil_gercekten_
cevrili` + gerçek metin dogrulamasi yapan yeni bir test; EN'e düşme
mantığı artık `monkeypatch` ile test ediliyor çünkü gerçek bir
çevrilmemiş dil kalmadı; tüm dillerin AYNI anahtar kümesine sahip olduğunu
doğrulayan bir test eklendi). `test_gui_qt.py` bölümündeki dil açılır
listesi testi "çevrilmedi" notunun ARTIK hiçbir dilde çıkmadığını
doğrulayacak şekilde güncellendi. `case_pill` regresyonu için ayrı bir
test eklendi. Toplam 315 test, hepsi yeşil.

---

## Ekran ölçeği (DPI) yuvarlama düzeltmesi -- native kapat düğmesi şikayeti

**Karar:** Kullanıcı gerçek makinesinde pencerenin sağ üst köşesindeki
native (Windows) kapat düğmesinin bir kısmının ekran dışında kaldığını
bildirdi. Kod tabanında herhangi bir OZEL baslik cubugu/kapat dugmesi
widget'i YOK (grep ile dogrulandi) -- bu OS'un kendi pencere cercevesi,
TriageChain'in cizmedigi bir sey. En olasi kok neden: `app.py`'de hicbir
DPI-farkindalik ayari YOKTU; kesirli ekran olcegi (%125/%150 gibi tam
sayi olmayan carpanlar) kullanan monitorlerde Qt'nin VARSAYILAN yuvarlama
politikasi widget'in dusundugu boyutla Windows'un GERCEKTE cizdigi boyut
arasinda bir uyusmazlik yaratabiliyor -- bu da
pencere cercevesinin (kapat dugmesi dahil) ekranin gercek sinirina gore
kaymis/tasmis GORUNMESINE yol acan, Qt+PyInstaller'da bilinen bir desen.

**Uygulanan duzeltme:** `app.py`'ye, `QApplication` kurulmadan HEMEN
once, `QGuiApplication.setHighDpiScaleFactorRoundingPolicy(Qt.
HighDpiScaleFactorRoundingPolicy.PassThrough)` eklendi -- Qt'ye olcegi
YUVARLAMADAN oldugu gibi kullanmasini soyleyip bu uyusmazligi ortadan
kaldirir.

**DOGRULANMADI -- bilerek acikca belirtiliyor:** Bu, offscreen test
ortaminin (QT_QPA_PLATFORM=offscreen, tum bu projenin testlerinin
kosulma bicimi) HICBIR ZAMAN uretmedigi gercek bir native pencere
cercevesi/OS-seviyesi geometri sorunu -- `QWidget.grab()` widget
ICERIGINI yakalar, OS'un cizdigi baslik cubugunu/kapat dugmesini
YAKALAMAZ. Bu yuzden bu duzeltmenin GERCEKTEN sorunu cozdugu, kullanicinin
kendi ekraninda (ozellikle kesirli olcek kullaniyorsa) elle test edilmeden
KANITLANAMAZ -- dusuk riskli, standart, yaygin olarak onerilen bir
duzeltme oldugu icin uygulandi ama "cozuldu" olarak ISARETLENMEDI.
