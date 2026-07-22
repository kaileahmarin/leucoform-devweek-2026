#!/usr/bin/env sh
set -eu

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PYTHON=${PYTHON:-python3}
TARGET=${1:-$(uname -s)}

cd "$PROJECT_ROOT"
"$PYTHON" -m pip install --disable-pip-version-check '.[desktop,dev]' 'pyinstaller>=6.10,<7'
"$PYTHON" -m ruff check src tests
"$PYTHON" -m mypy src/notug_protocol
QT_QPA_PLATFORM=offscreen "$PYTHON" -m pytest -q
"$PYTHON" -m PyInstaller --noconfirm --clean packaging/Leucoform.spec

mkdir -p dist
mkdir -p build/leucoform
"$PYTHON" -m pip inspect > build/leucoform/pip-inspect-private.json
"$PYTHON" scripts/sanitize_sbom.py \
  build/leucoform/pip-inspect-private.json dist/leucoform-sbom.json
rm -f build/leucoform/pip-inspect-private.json
cp LICENSE THIRD-PARTY-NOTICES.md dist/

case "$TARGET" in
  Darwin|macos)
    QT_QPA_PLATFORM=offscreen dist/Leucoform.app/Contents/MacOS/Leucoform --self-test
    rm -f dist/Leucoform.dmg
    hdiutil create -volname Leucoform -srcfolder dist/Leucoform.app -ov -format UDZO dist/Leucoform.dmg
    ;;
  Linux|linux)
    QT_QPA_PLATFORM=offscreen dist/Leucoform --self-test
    APPDIR=build/Leucoform.AppDir
    rm -rf "$APPDIR"
    mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/scalable/apps"
    cp dist/Leucoform "$APPDIR/usr/bin/Leucoform"
    cp packaging/linux/AppRun "$APPDIR/AppRun"
    cp packaging/linux/leucoform.desktop "$APPDIR/leucoform.desktop"
    cp packaging/linux/leucoform.desktop "$APPDIR/usr/share/applications/leucoform.desktop"
    cp src/notug_protocol/desktop/assets/leucoform.svg "$APPDIR/leucoform.svg"
    cp src/notug_protocol/desktop/assets/leucoform.svg "$APPDIR/usr/share/icons/hicolor/scalable/apps/leucoform.svg"
    chmod +x "$APPDIR/AppRun" "$APPDIR/usr/bin/Leucoform"
    : "${APPIMAGETOOL:?Set APPIMAGETOOL to an appimagetool executable}"
    ARCH=x86_64 "$APPIMAGETOOL" "$APPDIR" dist/Leucoform.AppImage

    DEBROOT=build/leucoform-deb
    rm -rf "$DEBROOT"
    mkdir -p "$DEBROOT/DEBIAN" "$DEBROOT/usr/bin" "$DEBROOT/usr/share/applications" "$DEBROOT/usr/share/icons/hicolor/scalable/apps"
    cp packaging/linux/control "$DEBROOT/DEBIAN/control"
    cp dist/Leucoform "$DEBROOT/usr/bin/Leucoform"
    cp packaging/linux/leucoform.desktop "$DEBROOT/usr/share/applications/leucoform.desktop"
    cp src/notug_protocol/desktop/assets/leucoform.svg "$DEBROOT/usr/share/icons/hicolor/scalable/apps/leucoform.svg"
    chmod +x "$DEBROOT/usr/bin/Leucoform"
    dpkg-deb --build --root-owner-group "$DEBROOT" dist/leucoform_0.1.0_amd64.deb
    ;;
  *)
    echo "Unsupported target: $TARGET" >&2
    exit 2
    ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
  find dist -maxdepth 1 -type f -print0 | sort -z | xargs -0 sha256sum > dist/SHA256SUMS
else
  find dist -maxdepth 1 -type f -exec shasum -a 256 {} \; > dist/SHA256SUMS
fi
