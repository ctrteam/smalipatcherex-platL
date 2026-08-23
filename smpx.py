#!/usr/bin/env python3
"""Entry point:  python smpx.py ..."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from smpx.cli import main

if __name__ == "__main__":
    sys.exit(main())
