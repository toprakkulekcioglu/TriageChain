# Sohbet Özeti — yeni bir oturuma başlarken önce bunu oku

Bu dosya, önceki (çok uzun) sohbetin context'i dolduğu için temizlenmeden
önce yazıldı — amacı, yeni bir Claude oturumunun bu projeye **sıfırdan
context okumadan** kaldığı yerden devam edebilmesi. Diğer `docs/*.md`
dosyaları hâlâ güncel ve asıl kaynak — bu dosya sadece "önce şuraya bak,
sonra ilgili detay dosyasına geç" haritası.

## Proje nedir

**TriageChain** — KAPE + Eric Zimmerman Tools (MFTECmd/RECmd/EvtxECmd/PECmd)
+ Hayabusa + Chainsaw + YARA + capa'yı tek otomatik pipeline'da
birleştiren, chain-of-custody standartlarına uygun bir DFIR (adli bilişim)
triaj sistemi. Proje kökü: `C:\Users\yasar\Desktop\TriageChain`.
Kullanıcının AYRI bir projesi olan **chameleon**
(`C:\Users\yasar\Desktop\chameleon`) ile karıştırılmamalı — TriageChain
kendi git deposu, kendi `.venv`'i, kendi test paketi.

## Şu an nerede duruyoruz (özet)

Çekirdek boru hattının TAMAMI bitti ve gerçek verilerle test edildi:
**toplama → chain-of-custody → yönlendirme → tespit (Hayabusa + Chainsaw,
iki bağımsız Sigma motoru) → YARA statik imza taraması → capa davranış/
yetenek analizi → raporlama (Yönetici + Uzman sekmeleri)**, artı gerçek
bir **PySide6 masaüstü uygulaması** (yedi sayfanın hepsi işlevsel) ve
standalone bir **`TriageChainKonsolu.exe`**. Toplam **175 test, hepsi
geçiyor** (`QT_QPA_PLATFORM=offscreen ./.venv/Scripts/python.exe -m
pytest -q`, proje kökünden). Hiçbir şey commit/push edilmedi — kullanıcı
commit'leri kendi zamanında kendisi yapacak.

## Nasıl çalıştırılır

- **Masaüstü uygulaması**: `C:\Users\yasar\Desktop\TriageChain\.venv\Scripts\triagechain-gui.exe`
  ya da paketlenmiş `TriageChainKonsolu.exe` (çift tıkla ya da PowerShell'den
  çalıştır). Açılınca üstteki "Vaka Konfigürasyonu Yükle" ile bir `.yaml`
  seçilir — hazır örnek: `config\triagechain.example.yaml`.
- **CLI**: aynı `.venv\Scripts\triagechain.exe` — `collect` / `route` /
  `detect` / `yara-scan` / `chainsaw-scan` / `capa-scan` / `report` /
  `verify-custody` alt komutları.
- **Testler**: `cd C:\Users\yasar\Desktop\TriageChain && QT_QPA_PLATFORM=offscreen .venv\Scripts\python.exe -m pytest -q`
  (GUI testleri gerçek bir ekran açmadan `offscreen` platformunda çalışır).

## Dosya haritası (`docs/` içinde kim ne anlatıyor)

| Dosya | İçeriği |
|---|---|
| `ozellikler.md` | Bitmiş özelliklerin tam listesi (kullanıcıya dönük) |
| `roadmap.md` | "Yapıldı" / "Daha sonra" (Plaso henüz yok; Volatility/Timesketch/RFC 3161 kapsam dışı) |
| `architecture.md` | Katmanlar, güvenlik kuralları, VSS/YARA/Chainsaw/capa/çoklu disk mimarisi |
| `chain_of_custody.md` | Hash-zincir şeması, TÜM custody olay tipleri (toplama/router/Hayabusa/YARA/Chainsaw/capa), çoklu-yazıcı kilidi |
| `config_reference.md` | Config YAML'inin alan alan açıklaması (YARA + Chainsaw + capa dahil) |
| `hatalar_ve_sonuclar.md` | Gerçek makinede bulunup düzeltilen somut hatalar |
| `ogrenilenler.md` | Genel/tekrarlanabilir dersler |
| `aldigim_kararlar.md` | **En önemli dosya** — kullanıcıya her seferinde sorulmadan alınan HER mimari/teknik kararın gerekçesi, kronolojik sırayla. Yeni bir oturum "neden böyle yapılmış" diye merak ederse önce burayı okusun. |
| `oturum_ozeti.md` | Bu sohbetin numaralı, madde madde özeti (1'den 18'e kadar fazlar/geliştirmeler) |
| `sohbet_ozeti.md` | Bu dosyanın kendisi |

## Tamamlanan fazlar/geliştirmeler (sırayla, detay `oturum_ozeti.md`'de)

1-11. Faz 1 (toplama + custody), Faz 2 (router), Faz 4 (Hayabusa tespit),
   Faz 5 (raporlama), RECmd `--bn` + metodoloji izlenebilirliği, VSS →
   `pywin32`, PySide6 masaüstü uygulamasının ilk sürümü (sadece Dashboard),
   görsel inceltme turu (SVG ikonlar, sparkline'lar).
12. Dashboard tasarımı bir referans ekran görüntüsüne göre **baştan**
    yazıldı; diğer beş sayfa (Vakalar, Delil Zinciri, Raporlar, Bulgular,
    Toplanan Dosyalar) tek tek işlevsel hale getirildi.
13. Gömülü fontlar (Inter + JetBrains Mono, OFL) + standalone
    `TriageChainKonsolu.exe` (PyInstaller `--onefile`).
14. **YARA** — Hayabusa'dan bağımsız, statik imza tabanlı ikinci tespit
    motoru; toplanan HER artefakt türü taranıyor.
15. **Chainsaw** — Hayabusa'nın AYNI kural klasörünü (`rules_dir`)
    paylaşan, BAĞIMSIZ ikinci bir Sigma motoru (gerçek çapraz doğrulama
    için). Raporlar "Yönetici Raporu"/"Uzman Raporu" olarak iki sekmeye
    ayrıldı; risk kuralı hem Sigma+YARA korelasyonunu hem Hayabusa+Chainsaw
    motor ittifakını hesaba katıyor. MITRE ATT&CK etiketleri eklendi; CVE
    entegrasyonu araştırılıp bilerek eklenmedi.
16. Roadmap'in kalan çekirdek maddeleri: VSS'te gerçek zaman aşımı, custody
    defterine gerçek çoklu-yazıcı desteği (stdlib dosya kilidi), çoklu
    disk/birim desteği (`additional_volumes`, sadece `$MFT`).
17. **capa** — PE davranış/yetenek analizi (gerçek capa 9.4.0). Bunun için
    toplama katmanına yeni bir kavram eklendi: `collection.suspicious_
    binaries` (analistin elle gösterdiği şüpheli `.exe`/`.dll` dosyaları —
    katalogdaki diğer hedefler gibi sabit bir konum değil). Veri modeli
    YARA'nın `YaraMatch`/`YaraManifest` şemasını yeniden kullanıyor.
    **Bilerek Yönetici Raporu'nun risk hesabına katılmıyor**: capa "yetenek"
    tespit ediyor, kötü amaçlı davranış değil — gerçek bir notepad.exe'de
    bile 35 capa kuralı eşleşti. CLI'ye `capa-scan`, GUI'ye "capa Tara"
    butonu + Bulgular sayfasına capa paneli eklendi.

## Şu an bekleyen / sıradaki kararlar (bkz. `roadmap.md` → "Daha sonra")

1. **Plaso/log2timeline** (süper zaman çizelgesi) — roadmap'te sıradaki,
   henüz başlanmadı.
2. Kapsam dışı bırakılanlar (kullanıcıdan ek onay gerektirir, kendi başına
   BAŞLANMAMALI): Volatility 3 (bellek analizi, projenin kendi roadmap'inde
   zaten kapsam dışı), Timesketch/ELK (web tabanlı çok kullanıcılı
   mimariye geçiş gerektirir), RFC 3161 zaman damgası (yeni bir üçüncü
   parti bağımlılık, çevrimdışı-öncelikli tasarımla gerilir).
3. Roadmap tükendiğinde: mevcut güvenlik-testi skill'leriyle uçtan uca bir
   güvenlik incelemesi.

## Kullanıcıyla ilgili önemli tercihler

- **Her yanıt Türkçe paragraf + altında İngilizce paragraf** şeklinde
  olmalı (tek akan paragraf, alt-başlıklara bölünmeden — karşılaştırma
  yapabilmesi için).
- Kendi başıma verdiğim her mimari/teknik kararı **`aldigim_kararlar.md`'ye
  o an, iş bitmeden ÖNCE** ekliyorum (başlık + Karar + Gerekçe + varsa
  Alternatif/Doğrulama).
- Yeni bir teknik terim/kavram (WMI, COM gibi) geçtiğinde **düz dilde kısaca
  açıklıyorum**, bilindiği varsayılmıyor.
- Mimari her zaman **ileride güncellenebilir** şekilde tasarlanmalı:
  kararlı genel arayüzler, değişebilir iç detaylar, kod yerine veri
  (YAML katalog) — Chainsaw'ın Hayabusa'nın var olan `Finding`/
  `DetectionManifest` şemasını hiç değiştirmeden yeniden kullanması buna
  somut bir örnek.
- Kullanıcı gerçek doğrulamayı çok önemsiyor: gerçek araçları (Hayabusa,
  Chainsaw, YARA, EvtxECmd, MFTECmd, RECmd) ve gerçek veri/örnek setlerini
  kullanarak varsayımları test etmemi istedi — bulunan HER gerçek hata
  `hatalar_ve_sonuclar.md`'ye işlendi.
- "Minimum bağımlılık, maksimum kalite" genel ilke — ama kör bir kural
  değil: `pywin32` ve `PySide6` gibi istisnalar, somut bir kalite/sağlamlık
  gerekçesiyle VE kullanıcı onayıyla kabul edildi.
- **Otonomi düzeyi göreve göre değişiyor**: kullanıcı bazı oturumlarda
  ("roadmapteki geliştirmeleri sırayla yap, bana bir şey sorma, kararları
  kendin al, sadece gerçekten çok önemli bir karar varsa onu sonraya
  bırak") büyük ölçüde onay beklemeden ilerlememi açıkça istedi — bu tür
  bir talimat varken küçük/orta kararlar için durup sormak YANLIŞ olur;
  talimat yoksa varsayılan hâlâ büyük/riskli işler (yeni bağımlılık, mimari
  değişiklik, kapsam dışı roadmap maddesi) öncesi onay istemektir.
