#!/bin/bash
set -e

# Version Extraction
VERSION=$(grep "version=" setup.py | cut -d"'" -f2)
echo "🚀 Starting builds for Heimdall v$VERSION..."

# 1. Clean up old artifacts (Need sudo for root-owned pycache)
echo "🔑 Requesting sudo to clean up locked build artifacts..."
sudo rm -rf dist/ build/ *.egg-info/ *.spec
sudo find . -name "__pycache__" -type d -exec rm -rf {} +
rm -f ../heimdall_*.deb ../heimdall_*.buildinfo ../heimdall_*.changes

# 2. Build Standalone Binary (PyInstaller)
echo "📦 Building Standalone Binary (PyInstaller)..."
.venv/bin/pyinstaller --onefile --clean --noconfirm \
    --name heimdall \
    --add-data "heimdall/services.json:." \
    --add-data "heimdall/services.sha256:." \
    run.py > /dev/null
echo "✅ Binary built: dist/heimdall"

# 3. Build Python Package (Wheel & Sdist)
echo "🐍 Building Python Package (Wheel/Sdist)..."
.venv/bin/python3 -m build > /dev/null
echo "✅ Python packages built."

# 4. Build Debian Package (.deb)
echo "🐧 Building Debian Package (.deb)..."
# Guard existing dist content from dpkg clean
mv dist dist_temp
dpkg-buildpackage -us -uc -b > /dev/null
mv dist_temp dist
mv ../heimdall_${VERSION}-1_all.deb dist/
echo "✅ Debian package built: dist/heimdall_${VERSION}-1_all.deb"

# 5. Fix permissions for dist
sudo chown -R $USER:$USER dist/

# Summary
echo ""
echo "🎉 RELEASE READY! Files in dist/:"
ls -lh dist/

# 6. Publish to GitHub (if gh is installed)
if command -v gh &> /dev/null; then
    echo "🚀 Publishing to GitHub..."
    gh release create v$VERSION dist/* --title "Heimdall v$VERSION" --notes-file RELEASE_NOTES.md
    echo "🎉 GITHUB RELEASE PUBLISHED SUCCESSFULLY!"
else
    echo "⚠️ 'gh' CLI not found. Please upload 'dist/' files manually to GitHub Releases."
    echo "   Use: gh release create v$VERSION dist/* --notes-file RELEASE_NOTES.md"
fi
