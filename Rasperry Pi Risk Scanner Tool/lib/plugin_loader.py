#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Tool
lib/plugin_loader.py  -  Plugin discovery, validation, and execution pipeline.

The loader scans the plugins/ directory for ScanPlugin subclasses, validates
them, orders them by phase, then executes the enabled ones in sequence against
a shared PluginContext.
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import os
import sys
import time
import traceback
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

# ── lib path must already be on sys.path before importing plugin_base ─────
from plugin_base import ScanPlugin, PluginContext, ALL_CATEGORIES, ALWAYS_ON

logger = logging.getLogger(__name__)

# Default plugins directory relative to the project root
_DEFAULT_PLUGIN_DIR = str(Path(__file__).parent.parent / "plugins")


# ══════════════════════════════════════════════════════════════════════════
# Discovery & validation
# ══════════════════════════════════════════════════════════════════════════

def _discover_plugin_classes(plugin_dir: str) -> list[type]:
    """
    Walk `plugin_dir`, import every *.py file, and collect all concrete
    ScanPlugin subclasses found.

    Returns a list of class objects (not instances).
    """
    plugin_dir_path = Path(plugin_dir)
    if not plugin_dir_path.exists():
        logger.warning(f"Plugin directory does not exist: {plugin_dir}")
        return []

    # Ensure the plugins directory is importable
    if str(plugin_dir_path) not in sys.path:
        sys.path.insert(0, str(plugin_dir_path))

    found_classes: list[type] = []
    seen_ids: set[str] = set()

    for py_file in sorted(plugin_dir_path.glob("*.py")):
        if py_file.name.startswith("_"):
            continue  # skip __init__.py etc.

        module_name = f"_awn_plugin_{py_file.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec is None or spec.loader is None:
                logger.warning(f"Could not load spec for {py_file.name}")
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)  # type: ignore[union-attr]
        except Exception as exc:
            logger.error(f"Failed to import plugin file {py_file.name}: {exc}")
            logger.debug(traceback.format_exc())
            continue

        # Collect all concrete ScanPlugin subclasses defined in this module
        for attr_name in dir(module):
            obj = getattr(module, attr_name)
            if (
                isinstance(obj, type)
                and issubclass(obj, ScanPlugin)
                and obj is not ScanPlugin
                and not getattr(obj, "__abstractmethods__", None)
            ):
                # Validate metadata
                instance = obj()
                errors = instance.validate()
                if errors:
                    logger.error(
                        f"Plugin {attr_name} in {py_file.name} has validation errors: "
                        + "; ".join(errors)
                    )
                    continue

                if instance.plugin_id in seen_ids:
                    logger.error(
                        f"Duplicate plugin_id '{instance.plugin_id}' in {py_file.name} — skipping"
                    )
                    continue

                seen_ids.add(instance.plugin_id)
                found_classes.append(obj)
                logger.debug(f"Discovered plugin: {instance!r} from {py_file.name}")

    logger.info(f"Plugin discovery complete: {len(found_classes)} plugin(s) found in {plugin_dir}")
    return found_classes


def load_plugins(
    plugin_dir: str = _DEFAULT_PLUGIN_DIR,
    categories: list[str] | None = None,
) -> list[ScanPlugin]:
    """
    Load, validate, and sort all plugins from `plugin_dir`.

    Args:
        plugin_dir:  Path to directory containing plugin *.py files.
        categories:  If provided, only plugins whose category is in this list
                     (plus ALWAYS_ON) will be included.  Pass None to load all.

    Returns:
        List of ScanPlugin *instances* sorted by phase (ascending).
    """
    classes = _discover_plugin_classes(plugin_dir)
    instances: list[ScanPlugin] = []

    for cls in classes:
        inst = cls()
        # Filter by category (policy-driven)
        if categories is not None:
            if inst.category not in ALWAYS_ON and inst.category not in categories:
                logger.debug(
                    f"Skipping plugin '{inst.plugin_id}' (category '{inst.category}' "
                    f"not enabled by policy)"
                )
                continue
        instances.append(inst)

    # Sort by phase
    instances.sort(key=lambda p: p.phase)
    logger.info(
        f"Loaded {len(instances)} plugin(s): "
        + ", ".join(f"{p.plugin_id}(phase={p.phase})" for p in instances)
    )
    return instances


# ══════════════════════════════════════════════════════════════════════════
# Execution pipeline
# ══════════════════════════════════════════════════════════════════════════

def run_plugins(
    plugins: list[ScanPlugin],
    ctx: PluginContext,
) -> PluginContext:
    """
    Execute each plugin in order, catching exceptions so one bad plugin
    cannot abort the entire scan.

    For each plugin:
      - Check ctx.module_enabled(plugin.category)
      - Check all plugin.requires have completed successfully
      - Call plugin.run(ctx)
      - Record success/failure and timing

    Returns the mutated PluginContext.
    """
    completed_ids: set[str] = set()
    failed_ids:    set[str] = set()

    for plugin in plugins:
        pid = plugin.plugin_id

        # Check policy gating (covers ALWAYS_ON too)
        if not ctx.module_enabled(plugin.category):
            logger.info(
                f"[{pid}] Skipped — category '{plugin.category}' not enabled by policy"
            )
            ctx.phases_skipped += 1
            continue

        # Check prerequisite plugins completed
        missing_reqs = [r for r in plugin.requires if r not in completed_ids]
        if missing_reqs:
            logger.warning(
                f"[{pid}] Skipped — required plugin(s) did not complete: "
                + ", ".join(missing_reqs)
            )
            ctx.phases_skipped += 1
            failed_ids.add(pid)
            continue

        logger.info(f"[Phase {plugin.phase}] Running plugin: {plugin.name} ({pid})")
        t0 = time.monotonic()
        try:
            plugin.run(ctx)
            elapsed = time.monotonic() - t0
            plugin._success = True
            completed_ids.add(pid)
            ctx.phases_completed += 1
            logger.info(f"[{pid}] Completed in {elapsed:.2f}s")
        except Exception as exc:
            elapsed = time.monotonic() - t0
            plugin._success = False
            plugin._error = str(exc)
            failed_ids.add(pid)
            ctx.phases_skipped += 1
            logger.error(f"[{pid}] Failed after {elapsed:.2f}s: {exc}")
            logger.debug(traceback.format_exc())

    return ctx


# ══════════════════════════════════════════════════════════════════════════
# Registry / introspection helpers
# ══════════════════════════════════════════════════════════════════════════

def get_plugin_registry(
    plugin_dir: str = _DEFAULT_PLUGIN_DIR,
) -> list[dict]:
    """
    Return a list of plugin metadata dicts (for the dashboard and API).
    Does NOT filter by policy — returns all installed plugins.
    """
    classes = _discover_plugin_classes(plugin_dir)
    registry: list[dict] = []
    for cls in classes:
        inst = cls()
        registry.append({
            "plugin_id":      inst.plugin_id,
            "name":           inst.name,
            "category":       inst.category,
            "phase":          inst.phase,
            "description":    inst.description,
            "version":        inst.version,
            "author":         inst.author,
            "requires":       inst.requires,
            "requires_root":  inst.requires_root,
            "modifies_hosts": inst.modifies_hosts,
        })
    registry.sort(key=lambda p: p["phase"])
    return registry
