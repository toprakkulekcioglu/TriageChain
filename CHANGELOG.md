# Değişiklik Günlüğü

## Unreleased

- İlk iskelet: toplama katmanı ve chain-of-custody modülü
- Faz 2: format dönüştürme/router katmanı (MFTECmd/RECmd/EvtxECmd/PECmd yönlendirmesi)
- Faz 4: Sigma kural tabanlı tespit katmanı (Hayabusa)
- Faz 5: otomatik raporlama (`triagechain report` → `report.json` + offline
  `report.html` + `report.json.sha256`)
- YARA statik imza taraması, Chainsaw (bağımsız ikinci Sigma motoru,
  Hayabusa ile çapraz doğrulama), capa (PE yetenek analizi), Yönetici/
  Uzman iki sekmeli rapor, PySide6 masaüstü arayüzü (altı işlevsel sayfa,
  gömülü Inter/JetBrains Mono fontları), çoklu disk + çoklu-yazıcı custody
  desteği, standalone `TriageChainKonsolu.exe`
- Birleşik zaman çizelgesi: MFTECmd/RECmd/EvtxECmd/PECmd çıktılarından
  (yeni bir dış araç eklemeden, Plaso'nun alternatifi olarak) kronolojik
  bir görünüm — `triagechain report`'a ve GUI'ye entegre
- Gerçek marka logosu tüm uygulamaya işlendi: exe simgesi, pencere ikonu,
  sidebar, README, HTML rapor başlığı
- İçe aktarma modu (`collection.source_root`): canlı bir Windows sistemine
  ihtiyaç olmadan, KAPE gibi başka bir araçla önceden toplanmış bir
  artefakt ağacı da analiz edilebiliyor; bu modda VSS hiç açılmıyor
- Windows `MAX_PATH` (260 karakter) sınırını aşan uzun yol hatası
  düzeltildi (`\\?\` uzun-yol öneki, sekiz dosyada)
- **"Yeni Vaka Oluştur" sihirbazı**: kullanıcı artık elle YAML yazmadan,
  KAPE'nin kendi arayüzündeki gibi kaynak (canlı sistem / klasör / ZIP-RAR-7z
  arşivi) ve hedef seçerek vaka oluşturabiliyor; konfigürasyon arka planda
  üretilip diske yazılıyor. Bir kaynak kökünde birden fazla makine varsa
  (gerçek KAPE `--zip` çıktısının kendi yapısı) hepsi tek seferde ayrı vaka
  olarak oluşturulabiliyor. Arşiv çıkartma arka plan iş parçacığında
  çalışıyor, arayüz donmuyor. Araç yolları (EZ Tools/Hayabusa/YARA/
  Chainsaw/capa) seçilen bir klasör altında otomatik aranabiliyor.
- Açık/koyu tema (Ayarlar sayfasında anında geçiş, GitHub Primer'in gerçek
  açık tema paletinden türetildi) ve çok dil altyapısı (TR/EN tam çevrili;
  ES/DE/PT/FR seçilebilir, henüz çevrilmedi) eklendi; sidebar navigasyonu
  artık dile bağlı olmayan sabit kimliklerle çalışıyor
