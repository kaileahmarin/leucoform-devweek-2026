# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
import platform

ROOT = Path(SPECPATH)
PROJECT = ROOT.parent

a = Analysis(
    [str(ROOT / "leucoform_entry.py")],
    pathex=[str(PROJECT / "src")],
    binaries=[],
    datas=[
        (str(PROJECT / "LICENSE"), "."),
        (str(PROJECT / "THIRD-PARTY-NOTICES.md"), "."),
        (str(PROJECT / "src" / "notug_protocol" / "desktop" / "assets"), "notug_protocol/desktop/assets"),
    ],
    hiddenimports=["PySide6.QtNetwork", "notug_protocol.desktop.main"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="Leucoform",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

if platform.system() == "Darwin":
    app = BUNDLE(
        exe,
        name="Leucoform.app",
        icon=None,
        bundle_identifier="local.leucoform.desktop",
        info_plist={
            "CFBundleDisplayName": "Leucoform",
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "12.0",
        },
    )
