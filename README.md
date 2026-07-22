# Leucoform packaging

Leucoform is frozen separately on each target operating system. No build cross-compiles Qt or claims another platform's native proof.

- Windows: run `scripts/build-leucoform.ps1` in a Python 3.11+ environment with Inno Setup 6. The result is `dist/installer/Leucoform-Setup.exe`.
- macOS: run `scripts/build-leucoform.sh macos`. The result is `dist/Leucoform.dmg` containing `Leucoform.app`.
- Linux: set `APPIMAGETOOL` to a trusted local AppImageKit executable and run `scripts/build-leucoform.sh linux`. The results are `dist/Leucoform.AppImage` and `dist/leucoform_0.1.0_amd64.deb`.

Each build runs Core and offscreen desktop tests, performs a frozen executable self-test, writes a dependency inventory, and hashes the produced files. Release publication is manual. Codesigning, notarization, and package signing are deliberately absent unless maintainers supply credentials in a controlled release environment; unsigned output is a development artifact.
