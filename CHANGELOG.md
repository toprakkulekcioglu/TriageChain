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
