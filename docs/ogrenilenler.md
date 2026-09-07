# Öğrenilenler

Bu proje boyunca ortaya çıkan, ileride tekrar karşılaşabileceğimiz teknik
dersler. Belirli bir hatanın adım adım çözümü için
[hatalar_ve_sonuclar.md](hatalar_ve_sonuclar.md)'a bakın — burası daha çok
"neden böyle davranıyor, bir dahaki sefere nasıl yaklaşmalı" notları.

## "Ücretsiz" ile "açık kaynak" farklı şeyler

KAPE (Kroll Artifact Parser and Extractor) örneği: ücretsiz dağıtılan bir
program otomatik olarak açık kaynak/yeniden-dağıtılabilir anlamına gelmez —
KAPE kapalı kaynak, kendi EULA'sıyla geliyor. Ama bir ekosistemin *verisi*
(KAPE'nin hedef/modül tanımları, `EricZimmerman/KapeFiles`) ayrı bir lisansla
gerçekten açık kaynak olabilir. Kapalı kaynaklı bir aracın *bilgisini*
(burada: "hangi artefakt diskte nerede durur") kullanmak, o aracın kendisini
çalıştırmaktan tamamen farklı bir bağımlılık profiline sahiptir. Böyle bir
ayrım netleşmeden "X açık kaynaklı, direkt kullanabiliriz" varsayımıyla
ilerlemek yanlış bir mimari karara yol açabilir.

## Dış süreç (subprocess) çağıran her katmanda üç savunma birlikte olmalı

Router katmanını tasarlarken üç ayrı savunmanın HİÇBİRİ tek başına yeterli
değildi, üçü birlikte gerekiyordu:

1. `shell=True` kullanmamak (argüman listesi) — kabuk enjeksiyonunu kökten
   kapatır ama girdinin GERÇEKTEN doğru dosyayı gösterdiğini garanti etmez.
2. Araç yolunun mutlak ve config'de sabit olması — hangi ikilinin çalıştığını
   netleştirir ama girdi dosyasının nereden geldiğini kontrol etmez.
3. Girdi yolunun, aracın kendi yönettiği çıktı ağacı (`output_dir/artifacts`)
   İÇİNDE olduğunun `Path.resolve()` + `is_relative_to()` ile doğrulanması —
   bu, kendi ürettiğimiz ama sonradan elle değiştirilebilecek bir ara veri
   dosyasına (`manifest.json`) bile körü körüne güvenmemek anlamına geliyor.
   `resolve()` kullanmak önemli: kontrol yol METNİNE değil (`..` ile
   kandırılabilir) çözülmüş GERÇEK hedefe uygulanıyor.

Genel kural: kendi ürettiğin bir ara dosyayı (manifest, config, cache) bile
"zaten bizim yazdığımız, güvenilir" diye görmemek — sonradan elle
değiştirilebileceğini varsayıp yine de doğrulamak, savunmayı gerçekten
anlamlı kılıyor.

## Harici/yavaş/güvenilmez süreçlere HER ZAMAN zaman aşımı

Bir dış program (EZ Tools gibi) `subprocess.run()` ile çağrıldığında, o
programın normalde hızlı çalışması "asla takılmaz" anlamına gelmiyor — bozuk
bir dosya, sonsuz döngüye giren bir parser, ya da askıda kalan bir I/O
beklemesi tüm koşuyu kilitleyebilir. `timeout` parametresi + `TimeoutExpired`
yakalama, dış araç çağıran her fonksiyonda varsayılan olmalı, "muhtemelen
gerek yok" diye atlanmamalı.

## Mock'larken NEREDE yamalandığı (patch) önemli

`subprocess.run`'ı test etmek için `unittest.mock.patch` kullanılırken,
modülün TANIMLANDIĞI yer değil KULLANILDIĞI yer yamalanmalı:
`patch("triagechain.router.runner.subprocess.run")`, `patch("subprocess.run")`
değil. Aksi halde `runner.py`'nin zaten `import subprocess` ile aldığı
referans yamadan etkilenmez, test sahte bir başarı gösterir ama gerçekte
gerçek `subprocess.run`'ı çağırmaya çalışır. Bu, gerçek EZ Tools ikilisi
olmayan bir geliştirme ortamında testlerin (yanlışlıkla) sessizce atlanması
ya da patlaması anlamına gelebilirdi.

## Belgelenmiş/varsayılan bir CLI davranışı, gerçek makinede test edilene kadar kanıtlanmış sayılmaz

İki ayrı örnekte de (Hayabusa'nın CLI sözdizimi, `vssadmin create shadow`'un
varlığı) ilk tasarım aşamasında "makul bir varsayımla" ilerlendi çünkü araç
o an test edilebilecek bir makinede yoktu. Kullanıcı gerçek bir makinede
gerçek testler yaptırınca İKİSİ DE yanlış çıktı: Hayabusa'nın 1.4.1 sürümü
alt komut kullanmıyordu ama güncel 4.0.0 sürümü kullanıyor (ikisi de
`csv-timeline` diye bir alt komuttan hiç geçmemişti); `vssadmin create
shadow` ise Microsoft tarafından istemci Windows sürümlerinde tamamen
kaldırılmış. Genel ders: bir dış aracın komut satırı davranışı hem
SÜRÜMLER ARASI hem de İŞLETİM SİSTEMİ SÜRÜMLERİ ARASI değişebilir —
"muhtemelen böyle çalışır" varsayımı, gerçek bir ortamda tek bir gerçek
çalıştırmayla doğrulanana kadar kod genelinde "varsayım" olarak açıkça
işaretlenmeli (bizim durumumuzda: kod değil veri dosyası olarak tutmak,
`docs/hatalar_ve_sonuclar.md`'de not düşmek) — asla sessizce kesin bilgi
gibi ele alınmamalı.

## Tanımadığın bir DSL'i elle yazıp debug etmek yerine aracın KENDİ resmi örneğini kullan

Chainsaw'ı gerçek verilerle doğrularken, elle yazılmış minimal bir Sigma
kuralı "geçerli tespit kuralı bulunamadı" hatasıyla yüklenmedi —
`status: test` → `status: stable` gibi kısmi düzeltmeler de işe yaramadı.
Kök nedeni derinlemesine kazmak yerine, Chainsaw'ın kendi resmi örnek
paketini (gerçek EVTX-ATTACK-SAMPLES + gerçek SigmaHQ kuralları) indirip
onunla denemek 8 gerçek tespitle ANINDA çalıştı. Genel ders: bir aracın
kendi DSL'inin (burada Sigma) TAM olarak hangi alanları/biçimi zorunlu
kıldığı belgelerden asla yüzde yüz çıkarılamaz — o aracın kendi "known-good"
örnek verisiyle başlamak, hatalı bir varsayımı satır satır debug etmekten
çok daha hızlı ve daha güvenilir bir doğrulama yoludur.

## İki motoru GERÇEKTEN bağımsız kılan şey aynı girdiyi paylaşmalarıdır, farklısı değil

Chainsaw'ı Hayabusa'ya "çapraz doğrulama" için eklerken ilk sezgi ayrı bir
`chainsaw_rules_dir` tanımlamak olabilirdi ("her motor kendi kural setini
kullansın"). Bu yanlış bir sezgidir: iki motor FARKLI kural setleriyle
farklı sonuçlar üretirse, bunların örtüşmesi/örtüşmemesi hiçbir şey
kanıtlamaz — sadece iki farklı sorunun cevaplarını karşılaştırmış olursun.
Gerçek çapraz doğrulama sinyali, AYNI kural setiyle çalışan iki BAĞIMSIZ
uygulamanın (farklı kod tabanı, farklı yorumlayıcı) aynı sonuca varmasından
gelir — bağımsızlık girdiden değil, uygulamadan gelmelidir. Bu yüzden
Chainsaw kasıtlı olarak Hayabusa'nın `detection.rules_dir`'ini paylaşıyor.

## Hash-zincirli defterde "vaka bazlı genesis" bilinçli bir tradeoff

Chain-of-custody defterinin genesis hash'i global değil, `case_id`'ye özel
(`sha256(case_id + "::TRIAGECHAIN_GENESIS")`). Bu, her vakanın delil
klasörünü (dosyalar + manifest + custody log) tek başına taşınabilir/
doğrulanabilir kılıyor — ama bir saldırganın FARKLI bir vakanın logunu bu
vakanınkiyle değiştirmesini bu zincir tek başına yakalamaz (her ikisi de
kendi içinde geçerli görünür). Bu bilinçli bir v0.1 kararı: çoklu-vaka çapraz
doğrulama, ileride RFC 3161 zaman damgası/harici kök hash yayınlama gibi bir
mekanizmayla ele alınacak (`CustodyEvent.payload.tsa_token` alanı bunun için
şimdiden ayrılmış durumda).
