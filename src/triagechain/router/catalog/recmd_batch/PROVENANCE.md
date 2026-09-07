# DFIRBatch.reb — kaynak ve sabitleme (pinning) bilgisi

Bu dosya, `DFIRBatch.reb`'in projeye NEREDEN, HANGİ sürümde gömüldüğünü
kaydeder — adli bilişim tekrarlanabilirliği (reproducibility) için önemli:
bir vakanın sonucu sorgulandığında "tam olarak hangi kural seti bu sonucu
üretti" sorusuna kod okumadan cevap verilebilsin.

- **Kaynak:** https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/DFIRBatch.reb
- **Lisans:** MIT (RECmd deposunun tamamı, `BatchExamples/` dahil)
- **Sürüm (dosyanın kendi başlığından):** 2.22
- **Git commit:** `3b6c153b3feab9bcab79228767c1d9971c71326a` (2026-03-18)
- **SHA-256 (bu projeye gömülen dosyanın):**
  `6fada377d185ab48f40b89f2dfb3f2f154db7b6753ed378b55fec4c4903b38b8`
- **Neden bu dosya:** `DFIRBatch.reb` (eski adıyla `Kroll_Batch`), KAPE'nin
  kendisinin de registry son-işleme adımında kullandığı, topluluk tarafından
  aktif bakımı yapılan standart RECmd toplu (batch) dosyasıdır. 2024'te
  isim değişikliği bilinçli olarak yapıldı ("Kroll dışındaki incelemeciler
  de lisans endişesi duymadan kullanabilsin diye") — bu, dosyanın genel
  kullanım/gömme niyetiyle yayınlandığının açık göstergesi.
- **Güncelleme:** Bu dosya elle (otomatik senkronize edilmeden) belirli bir
  sürüme sabitlenmiştir — RECmd'in kendi `--sync` bayrağı gibi "en güncelini
  indir" davranışı BİLEREK kullanılmadı, aksi halde aynı vaka farklı
  zamanlarda çalıştırıldığında farklı kural setiyle farklı sonuç üretebilir
  (tekrarlanabilirliği bozar). Güncellemek istenirse bu dosya elle, yeni
  sürümün kendi provenance bilgisiyle birlikte değiştirilmeli.
