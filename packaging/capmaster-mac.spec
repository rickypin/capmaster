# -*- mode: python -*-
"""PyInstaller spec for building the capmaster CLI on macOS."""

from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

ROOT_DIR = Path.cwd()
DIST_DIR = ROOT_DIR / "dist"
BUILD_DIR = ROOT_DIR / "build" / "capmaster-mac"

distpath = str(DIST_DIR)
workpath = str(BUILD_DIR)

plugin_modules = collect_submodules("capmaster.plugins")
analyze_modules = collect_submodules("capmaster.plugins.analyze.modules")
hidden_imports = sorted(set(plugin_modules + analyze_modules))

resource_patterns = ("*.txt", "*.yaml", "*.yml")
root_resources = []
resources_dir = ROOT_DIR / "resources"
if resources_dir.exists():
    for pattern in resource_patterns:
        for resource in resources_dir.glob(pattern):
            # Preserve the on-disk layout so docs/examples stay valid.
            target = Path("resources")
            root_resources.append((str(resource), str(target)))

capmaster_data = collect_data_files("capmaster", includes=["resources/*"])
all_resource_data = capmaster_data + root_resources


a = Analysis(
    [str(ROOT_DIR / "capmaster" / "cli.py")],
    pathex=[str(ROOT_DIR)],
    binaries=[],
    datas=all_resource_data,
    hiddenimports=hidden_imports,
    hookspath=[str(ROOT_DIR / "packaging" / "hooks")],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    exclude_binaries=False,
    name="capmaster",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
