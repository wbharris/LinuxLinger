"""LinuxLinger™ — live leftovers on this Linux host."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("linux-linger")
except PackageNotFoundError:
    __version__ = "0.1.0"

__all__ = ["__version__"]
