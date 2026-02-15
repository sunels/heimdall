dpkg-buildpackage -us -uc -b
sudo dpkg -i ../heimdall_0.5.0-1_all.deb

cd ..
gh release create v0.5.0 \
  heimdall_0.5.0-1_all.deb \
  --title "Heimdall v0.5.0 - Deep Inspect & Auto-Update" \
  --notes "Comprehensive system analysis, background service updates, and UI polish."
