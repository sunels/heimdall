## 📊 HTTP Accurate Monitor & Outbound Intelligence (v1.0.8)

This release introduces deep packet inspection for HTTP traffic and UI refinements for the Outbound Connections Modal.

### **✨ New Features (v1.0.8)**
- **HTTP Accurate Monitor (`S`)**: New sub-modal inside the Outbound Connections view that provides real-time, per-process HTTP endpoint analysis.
  - Automatically targets selected processes.
  - Shows Method, Host, and Path distribution.
  - Real-time hit counting and data volume tracking.
- **Enhanced Outbound Modal**: UI refinements to the footer and key bindings for better navigation.

### **🔧 Maintenance**
- Refactored internal signal handling for packet capture subprocesses.
- Optimized cleanup logic in modal windows to prevent memory leaks.

## 🛡️ Vulnerability Guard & NVD Stability (v1.0.7)

This patch focuses on the stability and accuracy of the background vulnerability scanner.

### **✨ Major Fixes (v1.0.7)**
- **NVD 404 Silence**: Resolved "NVD Error 404" noise in debug logs by gracefully handling missing CPE entries (common for local or custom processes). These are now silently cached as empty results to avoid API overhead.
- **Improved Service Fingerprinting**: Added high-confidence CPE mapping for common Linux services:
  - **CUPS** (cups-daemon)
  - **SSH/SSHD** (OpenSSH)
  - **Apache2** (HTTP Server)
  - **NTP**
- **Noise Reduction**: Automatically excludes internal and generic processes like `antigravity`, `sh`, and `bash` from vulnerability scans.

### **🚀 Core Recap (v1.0.6)**
- **Zero-Loss Traffic Tail**: High-performance OS-level file buffering for real-time traffic monitoring.
- **Smart Data Truncation**: UI-optimized 32KB tail reading for high-speed packet analysis.
- **UI Freeze (Space)**: Instantly lock lists for stable inspection.
