"""gui_qt/csv_export.py'nin testleri -- Qt gerektirmez."""

import csv

from triagechain.gui_qt import csv_export


def test_write_rows_csv_dosyayi_uretir_ve_basligi_yazar(tmp_path):
    path = tmp_path / "cikti.csv"
    csv_export.write_rows_csv(path, ["A", "B"], [["1", "2"], ["3", "4"]])

    assert path.is_file()
    with path.open(encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        rows = list(reader)
    assert rows == [["A", "B"], ["1", "2"], ["3", "4"]]


def test_write_rows_csv_turkce_karakterler_bom_ile_dogru_okunuyor(tmp_path):
    path = tmp_path / "turkce.csv"
    csv_export.write_rows_csv(path, ["BULGU"], [["Şüpheli Oturum Açma İşlemi"]])

    raw = path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")  # UTF-8 BOM -- Excel uyumlulugu

    with path.open(encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        rows = list(reader)
    assert rows[1][0] == "Şüpheli Oturum Açma İşlemi"


def test_write_rows_csv_alt_klasoru_olusturur(tmp_path):
    path = tmp_path / "alt" / "klasor" / "cikti.csv"
    csv_export.write_rows_csv(path, ["A"], [["1"]])
    assert path.is_file()


def test_write_rows_csv_bos_satir_listesi_sadece_baslik_yazar(tmp_path):
    path = tmp_path / "bos.csv"
    csv_export.write_rows_csv(path, ["A", "B"], [])

    with path.open(encoding="utf-8-sig") as handle:
        rows = list(csv.reader(handle))
    assert rows == [["A", "B"]]
