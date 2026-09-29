"""PyInstaller entry point for winvault.exe (command line)."""

import sys

from winvault.cli import main

if __name__ == "__main__":
    sys.exit(main())
