dpkg-buildpackage -us -uc -b
sudo dpkg -i ../heimdall_0.3.0-1_all.deb

cd ..
gh release create v0.3.0 \
  heimdall_0.3.0-1_all.deb \
  --title "Heimdall v0.3.0 - Kill Connections Feature" \
  --notes "See CHANGELOG for details"
