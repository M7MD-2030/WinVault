"""Generate packaging/version_info.txt (PyInstaller Windows version resource)
from winvault.__version__, so the .exe's Properties → Details show the right
product name and version."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # repo root, works uninstalled too
from winvault import PROJECT_NAME, __version__  # noqa: E402

parts = [int(p) for p in __version__.split(".")[:3]] + [0]
while len(parts) < 4:
    parts.append(0)
v = tuple(parts[:4])

TEMPLATE = f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={v}, prodvers={v}, mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'M7MD-2030'),
      StringStruct('FileDescription', {PROJECT_NAME!r}),
      StringStruct('FileVersion', '{__version__}'),
      StringStruct('InternalName', 'WinVault'),
      StringStruct('LegalCopyright', 'MIT License'),
      StringStruct('OriginalFilename', 'winvault.exe'),
      StringStruct('ProductName', 'WinVault'),
      StringStruct('ProductVersion', '{__version__}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""

out = Path(__file__).with_name("version_info.txt")
out.write_text(TEMPLATE, encoding="utf-8")
print(f"wrote {out} for version {__version__}")
