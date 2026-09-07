# Gömülü fontların kaynağı

Bu klasördeki font dosyaları TriageChain'in kaynak kodu DEĞİL — üçüncü
taraf, SIL Open Font License 1.1 (OFL) ile lisanslanmış açık kaynak font
dosyalarının belirli bir sürüme **sabitlenmiş** kopyalarıdır. OFL, tam
olarak bu kullanım için var: fontları yazılıma gömüp yeniden dağıtmaya
izin verir (bkz. her klasördeki `OFL.txt`).

## Neden gömülü (indirilmiyor/sisteme bağımlı değil)

Arayüz (`theme.py`) tasarım gereği Inter (UI metni) + JetBrains Mono
(hash/sayı gibi teknik veriler) kullanıyor — ikisi de bu tür bir güvenlik/
DFIR aracı için `ui-ux-pro-max` tasarım verisiyle de doğrulanmış bir
eşleştirme (JetBrains Mono özellikle "security tools" için öneriliyor).
Ancak bu fontlar kullanıcının makinesinde KURULU OLMAYABİLİR (gerçekten de
bir turda böyle çıktı, bkz. `docs/aldigim_kararlar.md`); Qt bu durumda
sessizce bir yedek fonta düşer ve tasarım bozulur. Çözüm: fontları
`assets/fonts/`'a göm, `app.py` başlangıçta
`QFontDatabase.addApplicationFont()` ile yükle -- artık hangi makinede
çalıştığından bağımsız olarak hep aynı font kullanılıyor.

## Sürüm / kaynak / doğrulama

| Aile | Sürüm | Kaynak | Lisans |
|---|---|---|---|
| Inter | v4.1 | https://github.com/rsms/inter/releases/tag/v4.1 | OFL 1.1 (`inter/OFL.txt`) |
| JetBrains Mono | v2.304 | https://github.com/JetBrains/JetBrainsMono/releases/tag/v2.304 | OFL 1.1 (`jetbrains_mono/OFL.txt`) |

Sadece kullanılan 4 ağırlık (Regular/Medium/SemiBold/Bold) vendor edildi;
her iki ailenin de İtalik, Black/ExtraBold/Thin gibi kullanılmayan
ağırlıkları/varyant dosyaları BİLEREK dahil edilmedi (gereksiz repo
boyutu). Değişken (variable) font yerine statik ağırlık dosyaları
seçildi: Qt/FreeType'ın değişken font agırlık eksenini her platformda
tutarlı eşlemesi garanti değil, statik dosyalar ağırlık başına net bir
eşleşme garantiler.

SHA-256 (indirilen resmi GitHub release zip'lerinden çıkarıldı, hiçbir
şey elle değiştirilmedi):

```
inter/Inter-Regular.ttf                    40d692fce188e4471e2b3cba937be967878f631ad3ebbbdcd587687c7ebe0c82
inter/Inter-Medium.ttf                     97ad806f526e41546d46365bb3a393145f75b7b1568913db74549ad8b8dba872
inter/Inter-SemiBold.ttf                   78a843fade9d4612a5567302fb595b56976eb5fcebf4fea5a5912d638bafcde3
inter/Inter-Bold.ttf                       288316099b1e0a47a4716d159098005eef7c0066921f34e3200393dbdb01947f
jetbrains_mono/JetBrainsMono-Regular.ttf   a0bf60ef0f83c5ed4d7a75d45838548b1f6873372dfac88f71804491898d138f
jetbrains_mono/JetBrainsMono-Medium.ttf    31c92d01a8a08528b718a43addf0ad3df0af2ca4b7b3290a452f70f358e14d3d
jetbrains_mono/JetBrainsMono-SemiBold.ttf  1b3bfa1ed5665a4ce3f9feb68d2d4e40e70bf8b4b7d9a3edd418f321b4e166a0
jetbrains_mono/JetBrainsMono-Bold.ttf      5590990c82e097397517f275f430af4546e1c45cff408bde4255dad142479dcb
```

Sürüm yükseltmek istenirse: yeni sürümün resmi GitHub release zip'i
indirilir, aynı 4 ağırlık dosyası çıkarılır, bu dosyanın üzerine yazılır
ve yukarıdaki tablo/sha256 güncellenir.
