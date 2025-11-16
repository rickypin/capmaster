"""Preprocess plugin package.

This package exposes the :class:`PreprocessPlugin` so that importing
``capmaster.plugins.preprocess`` triggers plugin registration via the
``@register_plugin`` decorator.
"""

from .plugin import PreprocessPlugin

__all__ = ["PreprocessPlugin"]

