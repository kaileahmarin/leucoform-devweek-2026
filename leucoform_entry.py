"""PyInstaller entry shim preserving the package import context."""

from notug_protocol.desktop.main import main

if __name__ == "__main__":
    raise SystemExit(main())
