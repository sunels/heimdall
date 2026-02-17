## 🚀 Release v0.6.0

**Heimdall is now cleaner, safer, and easier to install!**

### 📦 Major Architecture Changes
*   **Fully Packaged:** Heimdall is now a standard Python package. `heimdall.py` has moved to `heimdall/` directory.
*   **Standalone Binary:** Added pre-compiled binary support. Run `heimdall` anywhere, no Python needed!
*   **PyPI Support:** Ready for `pip install heimdall`.

### 🛡️ Security & Risk Assessment
Heimdall now actively scans services for known risks:
*   🚩 **High Risk Service:** Flags inherently dangerous services (Telnet, FTP, etc.).
*   ⚠️ **Security Audit:** Detects runtime threats like:
    *   Processes running as **ROOT**.
    *   Binaries listening on **0.0.0.0** (Public).
    *   **Deleted** executables (potential malware/tampering).

### 🛠️ Developer Improvements
*   Added `run.py` wrapper for easy local development.
*   New `services.json` + SHA256 integrity verification bundled in package.
*   Improved table alignment for emoji/icons.

### 📥 Installation
See updated `README.md` for details (Binary, Deb, Pip, Source).
