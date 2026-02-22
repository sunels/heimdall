#!/bin/bash
set -e

# ==============================================================================
# 🤖 AGENT GUIDE: HOW TO RELEASE HEIMDALL
# ==============================================================================
# 1. Update version in: 
#    - heimdall/__init__.py (parse_args)
#    - setup.py (version=...)
#    - PKGBUILD (pkgver=...)
# 2. Add an entry to 'debian/changelog' with the new version and changes.
# 3. Run this script: ./release.sh
# 
# The script will:
# - Verify version consistency across files.
# - Extract release notes from debian/changelog automatically.
# - Build binary, deb, and python packages.
# - Create a GitHub release with assets and notes.
# ==============================================================================

# Version Extraction & Verification
V_INIT=$(grep "version='heimdall " heimdall/__init__.py | cut -d"'" -f2 | awk '{print $2}')
V_SETUP=$(grep "version=" setup.py | cut -d"'" -f2)
V_DEB=$(head -n 1 debian/changelog | cut -d'(' -f2 | cut -d'-' -f1)
V_PKG=$(grep "pkgver=" PKGBUILD | cut -d"=" -f2)

echo "🔍 Verifying versions..."
echo "  __init__.py: v$V_INIT"
echo "  setup.py:    v$V_SETUP"
echo "  changelog:   v$V_DEB"
echo "  PKGBUILD:    v$V_PKG"

if [[ "$V_INIT" != "$V_SETUP" ]] || [[ "$V_SETUP" != "$V_DEB" ]] || [[ "$V_DEB" != "$V_PKG" ]]; then
    echo "❌ ERROR: Version mismatch! Please align version numbers in all files."
    exit 1
fi

VERSION=$V_SETUP
echo "🚀 Starting builds for Heimdall v$VERSION..."

# 1. Clean up old artifacts
echo "🧹 Cleaning up old artifacts..."
rm -rf dist/ build/ *.egg-info/ *.spec 2>/dev/null || true
# Only use sudo if permission denied
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# 2. Build Standalone Binary (PyInstaller)
echo "📦 Building Standalone Binary (PyInstaller)..."
.venv/bin/pyinstaller --onefile --clean --noconfirm \
    --name heimdall \
    --add-data "heimdall/services.json:." \
    --add-data "heimdall/services.sha256:." \
    --add-data "heimdall/system-services.json:." \
    --add-data "heimdall/system-services.sha256:." \
    --add-data "heimdall/sentinel_rules.json:." \
    --add-data "heimdall/heimdall.service:." \
    run.py > /dev/null
echo "✅ Binary built: dist/heimdall"

# 3. Build Python Package (Wheel & Sdist)
echo "🐍 Building Python Package (Wheel/Sdist)..."
.venv/bin/python3 -m build > /dev/null
echo "✅ Python packages built."

# 4. Build Debian Package (.deb)
echo "🐧 Building Debian Package (.deb)..."
# Use -nc to skip clean if permissions are an issue for fakeroot
dpkg-buildpackage -us -uc -b -nc > /dev/null
mkdir -p dist/
mv ../heimdall_${VERSION}-1_all.deb dist/ 2>/dev/null || mv ../heimdall_${VERSION}_all.deb dist/ 2>/dev/null || echo "⚠️ Could not move .deb"
echo "✅ Debian package built."

# 5. Extract Release Notes from debian/changelog
echo "📝 Extracting release notes from changelog..."
# Extracts the first block (from first line until the first line starting with ' --')
NOTES=$(sed -n '1,/^ --/p' debian/changelog | sed '$d')
echo "$NOTES" > dist/RELEASE_NOTES_TMP.md

# Summary
echo ""
echo "🎉 RELEASE READY! Files in dist/:"
ls -lh dist/

# 6. Publish to GitHub
if command -v gh &> /dev/null; then
    echo "🚀 Publishing to GitHub..."
    # Check if tag already exists to avoid error (optional)
    gh release create v$VERSION dist/* --title "Heimdall v$VERSION" --notes-file dist/RELEASE_NOTES_TMP.md || echo "⚠️ Release might already exist."
    rm dist/RELEASE_NOTES_TMP.md
    echo "🎉 GITHUB RELEASE COMPLETED!"
else
    echo "⚠️ 'gh' CLI not found. Manual upload required."
fi
