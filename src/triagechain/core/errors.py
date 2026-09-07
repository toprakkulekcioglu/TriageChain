"""TriageChain'e ozgu hata tipleri.

IntegrityError ve CustodyLedgerError kurtarilamaz durumlari temsil eder
(hash uyusmazligi, kirilmis custody zinciri, log yazilamamasi). Bu iki hata
kod tabaninda hicbir yerde sessizce yutulmaz; en tepeye kadar yukselir.
"""


class TriageChainError(Exception):
    """Tum TriageChain hatalarinin ortak atasi."""


class ConfigError(TriageChainError):
    """Konfigurasyon okunamadi ya da dogrulamadan gecemedi."""


class CollectionError(TriageChainError):
    """Toplama sirasinda olusan, genelde tek bir artefakti etkileyen hata."""


class IntegrityError(TriageChainError):
    """Butunluk ihlali: hesaplanan hash beklenenle uyusmuyor. Olumcul."""


class CustodyLedgerError(TriageChainError):
    """Chain-of-custody defteri yazilamadi/okunamadi ya da zincir kirik. Olumcul."""


class RouterError(TriageChainError):
    """Yonlendirme (router) katmaninda kurtarilamaz bir sorun (or. cikti dizini
    olusturulamadi: disk dolu, izin yok). Olumcul."""


class DetectionError(TriageChainError):
    """Tespit (detection) katmaninda kurtarilamaz bir sorun (or. cikti dizini
    ya da tespit manifesti yazilamadi: disk dolu, izin yok). Olumcul.

    RouterError ile ayni gerekce: bir dis aracin calismamasi olumcul degildir,
    ama ciktiyi/denetim izini hic yazamamak calismaya devam etmeyi anlamsiz
    kilar; ham OSError kullaniciya sizmadan tipli hataya sarilir."""


class ReportingError(TriageChainError):
    """Raporlama katmaninda kurtarilamaz bir sorun (or. rapor dosyalari
    yazilamadi: disk dolu, izin yok; ya da toplama manifesti hic yok). Olumcul.

    RouterError/DetectionError ile ayni gerekce: bu katman dis program
    calistirmaz, tek riski dosya okuma/yazmadir - ham OSError kullaniciya
    sizmadan tipli hataya sarilir."""
