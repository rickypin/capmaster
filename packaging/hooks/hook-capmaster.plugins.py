"""Hook to pull in every capmaster.plugins submodule for PyInstaller."""

from PyInstaller.utils.hooks import collect_submodules

hiddenimports = collect_submodules("capmaster.plugins")
