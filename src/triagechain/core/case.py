"""Vaka (case) modeli ve vaka kimligi dogrulamasi."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from triagechain.core.errors import ConfigError

# Vaka kimligi dosya sistemi yolu olarak kullanildigi icin sadece
# harf/rakam, tire ve alt cizgi kabul edilir.
_CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def validate_case_id(case_id: str) -> str:
    """Vaka kimligini dogrular ve aynen geri dondurur; gecersizse ConfigError."""
    if not case_id or not _CASE_ID_PATTERN.match(case_id):
        raise ConfigError(
            f"Vaka kimligi dosya sistemi icin guvenli degil: {case_id!r}. "
            "Sadece harf, rakam, '-' ve '_' kullanilabilir."
        )
    return case_id


@dataclass
class Case:
    """Tek bir adli vakayi temsil eder."""

    case_id: str
    operator: str
    description: str = ""
    opened_at_utc: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        # Kimlik daha nesne kurulurken dogrulanir, sonra guvenle yol olarak kullanilir.
        validate_case_id(self.case_id)
