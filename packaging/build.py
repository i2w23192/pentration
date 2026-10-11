"""Build the one-file allscan executable with PyInstaller.

Run from the repo root:  python packaging/build.py
Produces dist/allscan (dist/allscan.exe on Windows). PyInstaller cannot
cross-compile, so the Windows .exe must be built on Windows (the release CI
job does this).
"""

import subprocess
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller is not installed. Run: pip install pyinstaller")
        return 1
    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
           str(root / "packaging" / "allscan.spec")]
    print("Running:", " ".join(cmd))
    return subprocess.call(cmd, cwd=str(root))


if __name__ == "__main__":
    raise SystemExit(main())
