# Marka varlıkları — kaynak notu

Bu klasördeki logo dosyaları, diğer `PROVENANCE.md`'lerden (fontlar,
`recmd_batch/`) farklı olarak **üçüncü taraf lisanslı bir varlık değil** —
kullanıcının kendi ürettirdiği/sağladığı marka logosu. Buradaki not, o
yüzden bir lisans kaydı değil, sadece "hangi dosya nereden türedi" izini
taşıyor.

| Dosya | Kaynağı |
|---|---|
| `triagechain_logo_source.png` | Kullanıcının sağladığı orijinal logo (yatay dizilim: T/C + parmak izi simgesi + "TriageChain" kelime işareti + "DIGITAL FORENSIC" alt başlığı), 1774×887, 2026-09-08. |
| `triagechain_logo_square_source.png` | Aynı logonun kare (1254×1254) bir varyantı, "DİJİTAL ADLİ BİLİŞİM" alt başlıklı, 2026-09-08. |
| `triagechain_mark_square.png` | `triagechain_logo_source.png`'den **otomatik** olarak türetildi: arka plan rengine (koyu lacivert) göre sınır kutusu tespiti + kareye tamamlama (bkz. `scripts` altındaki değil, oturumun kendi PowerShell script'i — proje deposunda saklanmıyor, tekrar üretilebilir). Sadece simge (T/C + parmak izi), kelime işareti/alt başlık YOK. |
| `src/triagechain/gui_qt/assets/icons/app_icon.ico` | `triagechain_mark_square.png`'den, 16/32/48/64/128/256px çözünürlüklerde, PNG-gömülü ICO konteyneri olarak üretildi (yine PowerShell `System.Drawing`, ek bir araç/paket kurulmadı). PyInstaller'ın `.exe` simgesi VE Qt uygulama/pencere ikonu için kullanılıyor (bkz. `gui_qt/icons.py::app_icon()`).

**Kullanım yerleri:** PyInstaller `.exe` simgesi (`triagechain_gui.spec`),
Qt uygulama/pencere ikonu (`gui_qt/app.py`, `gui_qt/main_window.py`),
sidebar'daki marka simgesi (`main_window.py::_build_sidebar`), `README.md`
başlığı, `report.html`'in başlık alanı (base64 gömülü, offline-öncelikli
tasarım gereği harici referans yok).
