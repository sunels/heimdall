#!/bin/bash
set -e

# ==============================================================================
# 🚀 HEIMDALL RELEASE SCRIPT
# ==============================================================================
# 🤖 AGENT GUIDE: HOW THIS SCRIPT WORKS
# 1. It extracts the CURRENT_VERSION from setup.py.
# 2. It increments the version based on [patch|minor|major] or uses the provided version.
# 3. It updates version strings in:
#    - heimdall/__init__.py (CLI version arg)
#    - setup.py (PyPI metadata)
#    - PKGBUILD (Arch Linux package)
#    - debian/changelog (Debian package)
# 4. It cleans the dist/ folder to prevent conflict.
# 5. It builds:
#    - sdist & wheel for PyPI (using .venv if present)
#    - .deb package (using dpkg-buildpackage)
# 6. It uploads .tar.gz and .whl to PyPI using twine.
#    - REQUIRES: TWINE_USERNAME=__token__ and TWINE_PASSWORD=pypi-...
# 7. It creates a git commit, a git tag vX.Y.Z, and pushes to origin.
# 8. It creates a GitHub Release if 'gh' CLI is available.
#
# ℹ️ NOTE: The PyPI package name is 'heimdall-linux' because 'heimdall' was already taken.
# ==============================================================================

# 1. Parse Arguments
BUMP_TYPE=$1
TEST_MODE=false
if [[ "$2" == "--test" ]] || [[ "$1" == "--test" ]]; then
    TEST_MODE=true
    if [[ "$1" == "--test" ]]; then BUMP_TYPE=$2; fi
fi

if [[ -z "$BUMP_TYPE" ]]; then
    echo "❌ Usage: ./release.sh [patch|minor|major|x.y.z] [--test]"
    exit 1
fi

# 2. Check Prerequisites
PYTHON_CMD="python3"
TWINE_CMD="twine"
MISSING_TOOLS=()

if [[ -d ".venv" ]]; then
    PYTHON_CMD=".venv/bin/python3"
    TWINE_CMD=".venv/bin/twine"
elif [[ -d "venv" ]]; then
    PYTHON_CMD="venv/bin/python3"
    TWINE_CMD="venv/bin/twine"
fi

# Essential Python Tools
if ! $TWINE_CMD --version &> /dev/null || ! $PYTHON_CMD -m build --help &> /dev/null; then
    echo "❌ ERROR: 'build' or 'twine' not found. Install them with: pip install --upgrade build twine"
    exit 1
fi

# System Packaging Tools
if ! command -v dpkg-buildpackage &> /dev/null; then MISSING_TOOLS+=("dpkg-buildpackage"); fi
if ! command -v rpmbuild &> /dev/null; then MISSING_TOOLS+=("rpmbuild"); fi
if ! command -v pyinstaller &> /dev/null && ! [[ -f ".venv/bin/pyinstaller" ]] && ! [[ -f "venv/bin/pyinstaller" ]]; then 
    MISSING_TOOLS+=("pyinstaller"); 
fi

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    echo "⚠️  WARNING: Missing build tools: [${MISSING_TOOLS[*]}]"
    echo "This release will be INCOMPLETE and missing certain assets."
    read -p "Do you want to continue anyway? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Aborting release. Please install missing tools first."
        exit 1
    fi
fi

if [[ -z "$TWINE_PASSWORD" ]]; then
    echo "❌ ERROR: TWINE_PASSWORD environment variable set edilmemiş!"
    echo "Lütfen şu komutu çalıştırın: export TWINE_USERNAME=__token__ && export TWINE_PASSWORD=pypi-..."
    exit 1
fi
export TWINE_USERNAME=${TWINE_USERNAME:-__token__}

# 3. Get Current Version (Prefers Git tags, falls back to file)
CURRENT_VERSION=$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')
if [ -z "$CURRENT_VERSION" ]; then
    CURRENT_VERSION=$(cat heimdall/VERSION 2>/dev/null || echo "1.0.2")
fi
echo "🔍 Current version: $CURRENT_VERSION"

# 4. Calculate New Version
increment_version() {
    local version=$1
    local type=$2
    local IFS='.'
    read -ra parts <<< "$version"
    local major=${parts[0]}
    local minor=${parts[1]}
    local patch=${parts[2]}

    case "$type" in
        major) echo "$((major + 1)).0.0" ;;
        minor) echo "$major.$((minor + 1)).0" ;;
        patch) echo "$major.$minor.$((patch + 1))" ;;
        *) echo "$type" ;; # Direct version
    esac
}

VERSION=$(increment_version "$CURRENT_VERSION" "$BUMP_TYPE")
echo "🚀 Releasing Heimdall v$VERSION..."

# 5. Update Version Files (No source code edits!)
echo "📝 Updating version metadata..."
echo "$VERSION" > heimdall/VERSION
sed -i "s/pkgver=[0-9.]*/pkgver=$VERSION/" PKGBUILD
if [ -f "heimdall.spec" ]; then
    sed -i "s/Version:        [0-9.]*/Version:        $VERSION/" heimdall.spec
fi

# Update debian/changelog
if command -v dch &> /dev/null; then
    dch -v "${VERSION}-1" "Release v$VERSION"
else
    # Manual append if dch not available
    TIMESTAMP=$(date -R)
    CHANGELOG_ENTRY="heimdall ($VERSION-1) unstable; urgency=medium\n\n  * Release v$VERSION\n\n -- Serkan Sunel <serkan.sunel@gmail.com>  $TIMESTAMP\n"
    printf "$CHANGELOG_ENTRY\n$(cat debian/changelog)" > debian/changelog
fi

# 6. Clean up old artifacts
echo "🧹 Cleaning up old artifacts..."
rm -rf dist/ build/ *.egg-info/ 2>/dev/null || true
mkdir -p dist/

# 7. Build Python Package (Wheel & Sdist)
echo "🐍 Building Python Package (Wheel/Sdist)..."
$PYTHON_CMD -m build

# 8. Build Debian Package (.deb)
echo "🐧 Building Debian Package (.deb)..."
if command -v dpkg-buildpackage &> /dev/null; then
    dpkg-buildpackage -us -uc -b -nc > /dev/null || echo "⚠️ Debian build failed, skipping..."
    mv ../heimdall_${VERSION}-1_all.deb dist/ 2>/dev/null || mv ../heimdall_${VERSION}_all.deb dist/ 2>/dev/null || true
else
    echo "⚠️ 'dpkg-buildpackage' not found. Skipping .deb build."
fi

# 9. Build RPM Package (.rpm)
echo "🎩 Building RPM Package (.rpm)..."
if command -v rpmbuild &> /dev/null; then
    # We build only from spec for now, assumes source is available locally
    mkdir -p ~/rpmbuild/{SOURCES,SPECS,BUILD,RPMS,SRPMS}
    tar --exclude='.git' --transform "s,^\.,heimdall-${VERSION}," -czf ~/rpmbuild/SOURCES/v${VERSION}.tar.gz .
    rpmbuild -ba --nodeps heimdall.spec > /dev/null || echo "⚠️ RPM build failed, skipping..."
    cp ~/rpmbuild/RPMS/noarch/heimdall-${VERSION}-1*.rpm dist/ 2>/dev/null || true
else
    echo "⚠️ 'rpmbuild' not found. Skipping .rpm build."
fi

# 10. Build Standalone Binary (PyInstaller)
echo "📦 Building Standalone Binary (PyInstaller)..."
PYI_CMD="pyinstaller"
if [[ -f ".venv/bin/pyinstaller" ]]; then
    PYI_CMD=".venv/bin/pyinstaller"
elif [[ -f "venv/bin/pyinstaller" ]]; then
    PYI_CMD="venv/bin/pyinstaller"
fi

if command -v $PYI_CMD &> /dev/null; then
    # Use absolute paths for add-data to avoid issues with --specpath
    ROOT_DIR=$(pwd)
    $PYI_CMD --onefile --name heimdall_standalone --distpath dist/ --workpath /tmp/heimdall_build --specpath /tmp \
      --add-data "$ROOT_DIR/heimdall/services.json:heimdall" \
      --add-data "$ROOT_DIR/heimdall/system-services.json:heimdall" \
      --add-data "$ROOT_DIR/heimdall/sentinel_rules.json:heimdall" \
      --add-data "$ROOT_DIR/heimdall/VERSION:heimdall" \
      --hidden-import psutil --hidden-import curses --strip --log-level WARN heimdall/__main__.py || echo "⚠️ PyInstaller build failed."
else
    echo "⚠️ 'pyinstaller' not found. Skipping binary build."
fi

# 11. Upload to PyPI
if [ "$TEST_MODE" = true ]; then
    echo "🧪 Uploading to TestPyPI..."
    $TWINE_CMD upload --repository testpypi dist/*.tar.gz dist/*.whl || echo "⚠️ TestPyPI upload failed."
    PYPI_URL="https://test.pypi.org/project/heimdall-linux/$VERSION/"
else
    echo "🚀 Uploading to PyPI..."
    $TWINE_CMD upload dist/*.tar.gz dist/*.whl || echo "⚠️ PyPI upload failed (possibly version already exists)."
    PYPI_URL="https://pypi.org/project/heimdall-linux/$VERSION/"
fi

# 12. Git Tag & Push
echo "🏷️ Creating Git tag v$VERSION..."
if git rev-parse "v$VERSION" >/dev/null 2>&1; then
    echo "⚠️ Tag v$VERSION already exists."
else
    git commit -am "chore: release version $VERSION" || true
    git tag "v$VERSION"
    git push origin "v$VERSION"
    git push origin main
fi

# 11. GitHub Release (Optional)
if command -v gh &> /dev/null; then
    echo "🚀 Creating GitHub Release..."
    
    # Extract only the latest version's notes (everything until the next ## header)
    if [ -f "RELEASE_NOTES.md" ]; then
        awk '/^## /{count++} count==1{print} count==2{exit}' RELEASE_NOTES.md > /tmp/current_notes.md
        gh release create "v$VERSION" dist/* --title "Heimdall v$VERSION" --notes-file /tmp/current_notes.md || \
        gh release edit "v$VERSION" --notes-file /tmp/current_notes.md
        gh release upload "v$VERSION" dist/* --clobber
    else
        gh release create "v$VERSION" dist/* --title "Heimdall v$VERSION" --notes "Release v$VERSION via release.sh" || \
        gh release upload "v$VERSION" dist/* --clobber
    fi
fi

echo ""
echo "🎉 SUCCESS: Heimdall v$VERSION released!"
echo "📦 PyPI: $PYPI_URL"
