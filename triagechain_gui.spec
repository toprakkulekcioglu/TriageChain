# -*- mode: python ; coding: utf-8 -*-
"""TriageChain masaustu arayuzunu tek dosyalik, bagimsiz bir .exe'ye derler.

`python -m PyInstaller triagechain_gui.spec` ile calistirilir. Cikti:
`dist/TriageChainKonsolu.exe` -- hedef makinede Python KURULU OLMASI
GEREKMEZ, PySide6/pydantic/PyYAML dahil her sey exe'nin icine gomulu.

Veri dosyalari (datas) asagida ELLE listeleniyor, otomatik toplama YOK:
projenin kendi "her sey acik ve izlenebilir olsun" ilkesiyle tutarli --
pyproject.toml'daki [tool.setuptools.package-data] ile BIREBIR ayni liste,
biri degisirse digeri de guncellenmeli.
"""

from pathlib import Path

block_cipher = None
SRC = Path("src").resolve()

datas = [
    (str(SRC / "triagechain/gui_qt/assets/icons"), "triagechain/gui_qt/assets/icons"),
    (str(SRC / "triagechain/gui_qt/assets/fonts"), "triagechain/gui_qt/assets/fonts"),
    (str(SRC / "triagechain/collection/catalog"), "triagechain/collection/catalog"),
    (str(SRC / "triagechain/router/catalog"), "triagechain/router/catalog"),
    (str(SRC / "triagechain/detection/catalog"), "triagechain/detection/catalog"),
]

a = Analysis(
    [str(SRC / "triagechain/gui_qt/app.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    cipher=block_cipher,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="TriageChainKonsolu",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
