dpkg-buildpackage -us -uc -b
sudo dpkg -i ../heimdall_0.4.0-1_all.deb

cd ..
gh release create v0.4.0 \
  heimdall_0.4.0-1_all.deb \
  --title "Heimdall v0.4.0 - Precision Kill Tree & Performance" \
  --notes "See CHANGELOG for details"
