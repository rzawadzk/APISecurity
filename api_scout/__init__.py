"""API Scout — API Discovery & Inventory Tool."""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    # Source of truth: the version declared in pyproject.toml. Read at
    # import time so __version__, the dashboard, and the CLI all agree
    # without anyone having to remember three places.
    __version__ = _pkg_version("api-scout")
except PackageNotFoundError:  # pragma: no cover
    # Editable / source checkout where the package isn't installed —
    # fall back so imports still work in early development.
    __version__ = "0.0.0+unknown"
