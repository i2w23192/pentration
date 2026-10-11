# PyInstaller one-file spec for allscan (console app — it's a Textual TUI).
# Build:  pyinstaller packaging/allscan.spec   (run from the repo root)

import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd()))
from allscan import __version__

block_cipher = None

datas = [
    ("config.example.yaml", "."),
    ("README.md", "."),
]

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

a = Analysis(
    ["packaging/allscan_launcher.py"],
    pathex=[str(Path.cwd())],
    binaries=[],
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
    f"    StringStruct('FileDescription', 'allscan — authorized security recon'),\n"
    f"    StringStruct('FileVersion', '{__version__}'),\n"
    f"    StringStruct('ProductVersion', '{__version__}'),\n"
    "    StringStruct('InternalName', 'allscan'),\n"
    "    StringStruct('OriginalFilename', 'allscan.exe'),\n"
    "    StringStruct('LegalCopyright', 'Copyright i2w23192'),\n"
    "  ])]), VarFileInfo([VarStruct('Translation', [1033, 1200])])])"
)
_version_file = Path("packaging") / "_version_info.txt"
_version_file.write_text(version_info, encoding="utf-8")

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
    version=str(_version_file) if sys.platform == "win32" else None,
    icon="packaging/allscan.ico",
)
