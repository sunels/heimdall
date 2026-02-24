# Release Notes – Heimdall v1.0.0 (The Security Excellence Update) 🛡️🚀

## Highlights
- **📩 Background Vulnerability Scanner (NVD)**: Real-time system-wide CVE monitoring. Automatically matched with your installed packages via NVD API 2.0.
- **🔓 Deep Security Audit Integration**: Security vulnerabilities are now directly visible in the `Inspect (i)` modal and `Full System Dump (d)` at the process level.
- **🏷️ Smart Runtime Classification**: Advanced tech-stack detection. Identifies Java (Spring Boot), Node.js (Electron), Python (WSGI/ASGI), Go, Rust, PHP, and more.
- **🌍 Sudo-Aware Browser Support**: Opening links from a root-level TUI session now gracefully drops privileges to launch the browser in your user desktop.
- **📦 Smarter Package Matching**: Improved string-distance and substring matching to bridge the gap between NVD package names and local Ubuntu/Debian names.

## Bug Fixes & Improvements
- **NVD API Compliance**: Fixed 404/Bad Request errors by enforcing strict 120-day lookup windows.
- **UI Polish**: Added blinking alert indicators and refined 'System Health' pane rendering.
- **Stability**: Fixed a `TypeError` in the detail window's health rendering.
- **Performance**: Optimized background polling to ensure zero UI lag during NVD fetches.

This major release transforms Heimdall from a process viewer into a proactive security inspection desktop for Linux.
