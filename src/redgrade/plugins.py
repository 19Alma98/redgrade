"""Load extensions: your own detectors and classifiers, from modules or installed packages.

A plugin is a Python module that registers things when imported::

    # my_guards.py
    from redgrade import register_detector

    @register_detector("refund_over_limit", confidence="evidence")
    def refund_over_limit(ctx):
        ...

List it in ``redgrade.yaml`` (``plugins: [my_guards]``), import it before calling the SDK, or
ship it as a package with an entry point, loaded automatically by the CLI::

    [project.entry-points."redgrade.plugins"]
    acme = "acme_redgrade.detectors"          # a module, or a module:function called with no args
"""

import importlib
import os
import sys
from importlib.metadata import entry_points

__all__ = ["ENTRY_POINT_GROUP", "PluginError", "load_plugins"]

ENTRY_POINT_GROUP = "redgrade.plugins"

_LOADED: set[str] = set()


class PluginError(Exception):
    pass


def _load_one(spec: str) -> None:
    module_name, _, attr = spec.partition(":")
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise PluginError(f"cannot import plugin {spec!r}: {exc}") from exc
    if attr:
        fn = getattr(module, attr, None)
        if not callable(fn):
            raise PluginError(f"plugin {spec!r}: {attr} is not callable")
        fn()


def load_plugins(modules: list[str] | None = None, *, installed: bool = True) -> list[str]:
    """Import plugin modules (``pkg.mod`` or ``pkg.mod:setup``) and, with ``installed``, every
    entry point in the ``redgrade.plugins`` group. Each is loaded once; returns what was loaded."""
    loaded: list[str] = []
    specs = list(modules or [])
    if installed:
        specs += [ep.value for ep in entry_points(group=ENTRY_POINT_GROUP)]
    cwd = os.getcwd()
    if cwd not in sys.path:
        sys.path.insert(0, cwd)  # plugins next to redgrade.yaml are importable, like targets
    for spec in specs:
        if spec in _LOADED:
            continue
        _load_one(spec)
        _LOADED.add(spec)
        loaded.append(spec)
    return loaded
