"""Precinto — control de salida para paquetes de diagnóstico."""

__version__ = "0.1.0"          # reserva para cuando se corre desde el checkout

from .cli import main          # noqa: F401

__all__ = ["main", "__version__"]
