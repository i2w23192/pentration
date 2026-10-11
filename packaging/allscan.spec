# PyInstaller one-file spec for allscan (console app — it's a Textual TUI).
# Build:  python packaging/build.py   (or: pyinstaller packaging/allscan.spec)

import os
import sys

from PyInstaller.utils.hooks import collect_all

SPEC_DIR = os.path.abspath(SPECPATH)
ROOT = os.path.dirname(SPEC_DIR)
sys.path.insert(0, ROOT)
from allscan import __version__

block_cipher = None

datas = [
    (os.path.join(ROOT, "config.example.yaml"), "."),
    (os.path.join(ROOT, "README.md"), "."),
]
binaries = []
hiddenimports = [
    "allscan.base", "allscan.engine", "allscan.config", "allscan.models",
    "allscan.utils", "allscan.scope", "allscan.report", "allscan.report_pdf",
    "allscan.notify", "allscan.platform", "allscan.mapping",
    "allscan.netdiscover", "allscan.recon", "allscan.dnsx", "allscan.whois_rdap",
    "allscan.asn", "allscan.certs", "allscan.email_sec", "allscan.scan",
    "allscan.web", "allscan.fingerprint", "allscan.headers", "allscan.tls",
    "allscan.cloud", "allscan.waf", "allscan.integrations", "allscan.active",
    "allscan.vulns", "allscan.exploitrefs", "allscan.vulnintel",
    "allscan.surface", "allscan.threatmodel", "allscan.compliance",
]

# textual/rich ship CSS and other package data that must be bundled; dns and
# yaml have submodules PyInstaller can miss.
for pkg in ("textual", "rich", "dns", "yaml"):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

a = Analysis(
    [os.path.join(SPEC_DIR, "allscan_launcher.py")],
    pathex=[ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

_v = tuple(int(x) for x in (__version__.split(".") + ["0", "0", "0"])[:4])
version_info = (
    "VSVersionInfo(\n"
    f"  ffi=FixedFileInfo(filevers={_v}, prodvers={_v}, mask=0x3f, flags=0x0,\n"
    "    OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),\n"
    "  kids=[StringFileInfo([StringTable('040904B0', [\n"
    "    StringStruct('CompanyName', 'i2w23192'),\n"
    "    StringStruct('ProductName', 'allscan'),\n"
    "    StringStruct('FileDescription', 'allscan — authorized security recon'),\n"
    f"    StringStruct('FileVersion', '{__version__}'),\n"
    f"    StringStruct('ProductVersion', '{__version__}'),\n"
    "    StringStruct('InternalName', 'allscan'),\n"
    "    StringStruct('OriginalFilename', 'allscan.exe'),\n"
    "    StringStruct('LegalCopyright', 'Copyright i2w23192'),\n"
    "  ])]), VarFileInfo([VarStruct('Translation', [1033, 1200])])])"
)
_version_file = os.path.join(SPEC_DIR, "_version_info.txt")
with open(_version_file, "w", encoding="utf-8") as fh:
    fh.write(version_info)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="allscan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    runtime_tmpdir=None,
    console=True,
    version=_version_file if sys.platform == "win32" else None,
    icon=os.path.join(SPEC_DIR, "allscan.ico"),
)
