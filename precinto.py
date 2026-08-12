#!/usr/bin/env python3
"""Envoltorio: `python3 precinto.py …` sigue funcionando desde el checkout.

Existe para no romper las instrucciones ya publicadas en el sitio, en el
repositorio y en los correos enviados. La implementación vive en `precinto/cli.py`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from precinto.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
