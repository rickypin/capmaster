"""Hook to ensure analyze module registry is bundled."""

from PyInstaller.utils.hooks import collect_submodules

hiddenimports = collect_submodules("capmaster.plugins.analyze.modules")
