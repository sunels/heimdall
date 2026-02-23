          ██╗  ██╗███████╗██╗███╗   ███╗██████╗  █████╗ ██╗     ██╗     
          ██║  ██║██╔════╝██║████╗ ████║██╔══██╗██╔══██╗██║     ██║     
          ███████║█████╗  ██║██╔████╔██║██║  ██║███████║██║     ██║     
          ██╔══██║██╔══╝  ██║██║╚██╔╝██║██║  ██║██╔══██║██║     ██║     
          ██║  ██║███████╗██║██║ ╚═╝ ██║██████╔╝██║  ██║███████╗███████╗
          ╚═╝  ╚═╝╚══════╝╚═╝╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝

**Interactive terminal-based port, process, file, and resource inspector for Linux**

`heimdall` is a high-performance, **curses-based Terminal User Interface (TUI)** designed to give you **instant visibility and control** over your Linux system — all from a single, interactive view.

## ✨ Features

- 🔍 **Live port listing** using `ss`
- ⚡ Shows **CPU% / MEM% usage** per process
- 🧠 Maps **PORT → PID → PROGRAM**
- ⛔ **Firewall toggle** for selected port (temporarily block/unblock traffic)
- 📂 Displays **all open files** of the selected process (`/proc/<pid>/fd`)
- 🧾 Deep inspection via **`witr --port`**
- 🖥️ Fully interactive **terminal UI (curses)**
- ⚡ Real-time refresh
- 🛑 Stop a **process or systemd service** directly from the UI (with confirmation)
- 📝 Warnings annotation (e.g., suspicious working directory is flagged but explained)
- 🛠️ **Action Center (Modal)** — quick operational panel for ports & processes (see below)
- 💥 **Kill Connections** operation: list and kill established connections for a port.
- 🚫 **Block IP** operation: block a source IP for a port via iptables.
- 🔍 **Deep Inspect / Info (i)**: Real-time ancestry tracking, resource pressure, and security audit.
- 🎬 **Service Activity History**: Extract historical logins, IP events, and session logs from system journals.
- 📡 **Live Auto-Scan**: Periodic background refresh of the port list (adjustable speed).
- 📸 **Full System Dump (d)**: Comprehensive text report of all active services, including logs, process trees, and resource limits.
- 📦 **Local Package Intelligence**: Automatic fallback to local package managers (dpkg/rpm) for rich service details when other sources fail.
- 🛡️ **Heimdall Sentinel (Security Audit)**:
  - 🚩 **Risk Level**: Flags known high-risk services (e.g., FTP, Telnet) based on a built-in vulnerability database.
  - ☢️ **Behavioral Analysis**: Real-time alerts for Backdoors, Masquerading, Script Listeners, and other anomalies.
- 🔄 **Auto Service Updates**: Background synchronization of `services.json` from GitHub.
- ⚙️ **Settings Console (p)**: Configuration modal for updates and system preferences.
- 🔍 **Interactive System Filter (F)**: Real-time filtering by Port, PID, or User directly from the TUI.
- ⚙️ **System Services Manager (z)**: Integrated systemd service management.
  - 🔄 **Units vs Files (TAB)**: Toggle between active/running units and all installed unit files on disk.
  - 🛠️ **Full Actions**: Start, stop, restart, reload, and edit unit files directly.
  - ℹ️ **Intelligence (i)**: Explain systemd terminology and clarify `alias` / `static` states.
- 🌳 **Precision Kill Tree**: Nuclear termination for script loops that protects your terminal.
- 🛡️ **Daemon Mode (Background)**: Non-interactive monitoring with automatic suspicious-outbound detection and mitigation.
- 🛡️ **Active TUI Protection**: Proactive security enforcement in the TUI when the daemon is inactive (auto-suspends suspicious processes).
- ⚖️ **Process Priority (Renice)**: Detailed modal to change CPU priority with real-time feedback.
- ☠️ **OOM Score Adjustment**: Control which processes Linux sacrifices during RAM shortage.
- ⏸️ **Tree-Aware Pause/Continue**: Freezes both the process and its script loop parent.
- 🐞 **Internal Debug Logging**: Trace complex process behaviors in `~/.config/heimdall/debug.log`.
- 🧩 Modal UX: monospace, standard curses box(), 2-space padding, reverse+bold highlights.

---

It enables you to seamlessly navigate the full relationship between:

> **Open ports → owning processes → CPU & memory usage → firewall rules → files in use**

This eliminates the need to jump between multiple tools such as `ss`, `netstat`, `lsof`, `top`, or firewall utilities.

---

![heimdall logo](https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/logo.png)

---

## Core Navigation

```text
heimdall
├─ 🌐 Ports              View all open ports and their states
├─ ⚡ Usage (CPU/Mem)    Real-time resource consumption per process
├─ 🧠 Processes          Process inspection and ownership mapping
├─ ⛔ Firewall Toggle    Enable/disable firewall rules interactively
└─ 📂 Open Files         Files and sockets used by each process
```
---

## 🧠 What Makes It Special?

Unlike classic tools that show *only one layer* (`ss`, `netstat`, `lsof`),  
**heimdall connects everything together**:

🔌 **Port** → ⚡ **CPU/MEM Usage** → 🧠 **Process / Service** → ⛔ **Firewall Control** → 📂 **All open files**

---

## 📸 Screenshots

### 🔍 Main View — Ports, Processes & Open Files
<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-1.png" alt="heimdall main view" width="100%"/>

---

### 🧾 Detail View — Deep Port & Process Inspection
<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-2.png" alt="heimdall detail view" width="100%"/>

---
### 🧾 Detail View — Actions Center (Modal)
<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-3.png" alt="heimdall detail view" width="100%"/>

---
### 🧾 Detail View — Block IP Modal
<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-4.png" alt="heimdall detail view" width="100%"/>

---
### 🧾 Detail View — Connection Limit Modal
<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-5.png" alt="heimdall connection limit" width="100%"/>

---
### 🧾 Color Palette — Happy eyes edition
<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-6.png" alt="heimdall color palette" width="100%"/>

---

### 🔍 Deep Inspection — Static Service Analysis & Risk Audit
<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-7.png" alt="heimdall deep inspection" width="100%"/>

---

### 🔍 Deep Activity History — Historical Log Intelligence
<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-8.png" alt="heimdall activity history" width="100%"/>

---

### 💾 Full System Dump — Visual Progress & Archive
<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-9.png" alt="heimdall system dump" width="100%"/>

---

### 🔍 Interactive System Filter — Real-time TUI Filtering
<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-10.png" alt="heimdall system filter" width="100%"/>

---

### 🛡️ Heimdall Sentinel — Behavioral Security Intelligence
<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-11.png" alt="heimdall sentinel analysis" width="100%"/>

---

### 🛡️ Sentinel Deep Audit — Intelligent Risk Scoring
<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-12.png" alt="heimdall sentinel detailed audit" width="100%"/>

---

### 🛡️ Sentinel Report — Security Executive Summary
<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-13.png" alt="heimdall sentinel executive summary report" width="100%"/>

---

### ⚙️ System Services Manager (z) — View & Control Units (Active)
<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-14.png" alt="heimdall services manager" width="100%"/>

---

### ⚙️ System Services Manager — Info & Help (i)
<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-15.png" alt="heimdall services info" width="100%"/>

---

### 📂 System Services Manager — All Unit Files (TAB)
<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-16.png" alt="heimdall all unit files" width="100%"/>

---


## 🎮 Key Bindings

### 🖥️ Main View

| Key | Action |
|-----|--------|
| ↑ / ↓ | Move selection |
| + / - | Resize table height |
| → / ← | Scroll open files |
| r | Refresh port list |
| Tab | Switch to detail view |
| s | Stop selected process / service |
| f | Toggle firewall for selected port |
| a | Actions (open Action Center modal) |
| i | Inspect / Deep Information modal |
| F | Filter (Port, PID, User modal) |
| z | System Services Manager modal (TAB to switch view, 'i' for info) |
| d | Full System Dump (Reports all services/units to file) |
| p | Settings (Auto-update, etc.) |
| q | Quit |

### 📜 Detail View (witr output)

| Key | Action |
|-----|--------|
| ↑ / ↓ | Scroll |
| Tab | Back to main view |
| q | Quit |

---

## 🧠 How It Works

1. **Port discovery**
    - `ss -lntuHp`
2. **Process resolution**
    - Extracts PID & program name from socket metadata
3. **CPU/Mem usage**
    - Uses `ps -p <pid> -o pcpu=,pmem=` for human-readable metrics
4. **Open file inspection**
    - Reads `/proc/<pid>/fd`
5. **Deep context**
    - Calls `witr --port <port>` and annotates warnings
6. **Control**
    - Optional process / service stop via `systemctl` or `kill`
    - Temporary firewall block/unblock via F key

---

## 🧪 Requirements

- 🐧 **Linux only**
- 🐍 Python **3.6+**
- Required system tools:
    - `ss` (iproute2)
    - `systemctl`
    - `/proc` filesystem
    - `witr` (**mandatory**)
    - `ps`
    - `iptables` / `ufw` (for firewall toggle)
- 🔐 `sudo` access required for:
    - `witr`
    - stopping processes/services
    - firewall rule management
    - full `/proc` visibility

---

## 🚀 Installation & Quick Start
 
Choose the installation method that fits your workflow.
 
#### 🔄 Update
To update, simply download the latest binary and replace the old one.
 
---
 
### 🐧 Option 2: Debian / Ubuntu (.deb)
*Native system integration.*
 
Download the `.deb` package from [Releases](https://github.com/sunels/heimdall/releases) layer:
 
```bash
sudo dpkg -i heimdall_0.9.7-1_all.deb
# If dependencies are missing:
sudo apt update && sudo apt install -f
```

#### 🔄 Update
Download the new `.deb` file and run the same command:
```bash
sudo dpkg -i heimdall_0.9.7-1_all.deb
```
 
---
 
### 🎩 Option 3: Fedora / RHEL / CentOS (.rpm)
*Native RPM support.*
 
```bash
# Build the RPM package
rpmbuild -ba heimdall.rpm.spec

# Install the generated RPM
sudo dnf install ~/rpmbuild/RPMS/noarch/heimdall-0.9.7-1.noarch.rpm
```

#### 🔄 Update
Rebuild and reinstall the RPM:
```bash
sudo dnf upgrade ~/rpmbuild/RPMS/noarch/heimdall-0.9.7-1.noarch.rpm
```
 
---

### 🏔️ Option 4: Arch Linux
*Native Arch Linux package.*

```bash
# Build and install using the provided PKGBUILD
makepkg -si
```

#### 🔄 Update
Pull the latest changes and rebuild:
```bash
git pull origin main
makepkg -si
```

---

 
### 🐍 Option 5: Python / Pip
*For Python users.*
 
You can install directly from PyPI:
 
```bash
pip3 install heimdall-linux
```

#### 🔄 Update
To upgrade to the latest version via PyPI:
```bash
sudo pip3 install --upgrade heimdall-linux --break-system-packages
```

Or install from the latest wheel:
```bash
pip3 install heimdall-0.9.7-py3-none-any.whl
```
*(Note: Requires `witr` installed separately)*
 
---
 
### 🛠️ Option 6: Development (Source)
*For contributors.*
 
Clone the repo and prepare the environment:
 
```bash
git clone https://github.com/sunels/heimdall.git
cd heimdall
 
# Install dependencies (psutil, etc.) in editable mode
pip3 install -e .

# Run directly using the wrapper script:
sudo python3 run.py
```

#### 🔄 Update
Update the source code:
```bash
git pull origin main
```

## 🛡️ Daemon Mode (Background Protection)

Heimdall can run as a background daemon to monitor your system 24/7. It specifically watches for **new outbound connections** from processes that are already flagged as "Suspicious" by the Sentinel logic.

### 🚀 Usage
```bash
# Start manually in background
sudo heimdall --daemon

# Or enable via Settings (p) -> Daemon Mode: ON
```

### 🧠 How it protects
1. **Detection**: Daemon polls connections every few seconds.
2. **Flagging**: If a process with a HIGH/CRIT danger level (e.g. deleted binary, /tmp CWD) tries to connect to the internet.
3. **Suspension**: Daemon immediately sends `SIGSTOP` to the process.
4. **Approval**: 
   - If the Heimdall TUI is open, it pops up a **Priority Alert Modal** for you to Allow or Kill.
   - If the TUI is closed, it sends a System Notification (`notify-send`) and waits 30s.
5. **Enforcement**: If denied or timed out, the process is **Permanently Killed** (`SIGKILL`).

### ⚙️ Systemd Installation
To run Heimdall as a persistent system service:

1. Copy the provided service file:
   `sudo cp heimdall.service /etc/systemd/system/`
2. Enable and start:
   `sudo systemctl enable --now heimdall`
3. Check status/logs:
   `sudo systemctl status heimdall`
   `journalctl -u heimdall -f`

---

## 🛡️ Sentinel & Daemon Mode: The Safety Story

Heimdall isn't just a viewer; it's a **proactive guardian**. Here is how the Sentinel engine and Daemon mode work together to protect your system:

### 1. Advanced Risk Auditing
When you use the TUI, Heimdall Sentinel performs a deep dive into every listener. Below, it identifies an outdated `vsftpd` service running as **root** and flags it as **High Risk**, explaining exactly why it's a brute-force magnet.

<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-17.png" alt="Sentinel risk audit" width="100%"/>

---

### 2. Going "Hands-Free" with Daemon Mode
By running `heimdall --daemon`, you move the security logic into the background. It stays silent until a truly suspicious event occurs — like a script-managed backdoor attempt.

<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-18.png" alt="Starting daemon mode" width="100%"/>

---

### 3. Real-time Intervention
The moment a suspicious process (like a hidden `nc` listener) tries to open a port, the Daemon **immediately suspends** it and prompts you with a high-priority intervention modal.

<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-19.png" alt="Daemon interception modal" width="100%"/>

---

### 4. System-Wide Alerts
If you are working in another terminal, Heimdall sends a **wall broadcast** to all TTYs and a **native desktop notification**, ensuring you never miss a security event even if the TUI is closed.

<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-20.png" alt="Broadcast alert" width="100%"/>

---

### 5. Active TUI Protection (Proactive Intervention)
When the Daemon is not running, the Heimdall TUI takes over security enforcement. It instantly **suspends** any suspicious process detected during a scan and prompts you via a high-priority modal to decide its fate.

<img src="https://raw.githubusercontent.com/sunels/heimdall/main/screenshots/pp-21.png" alt="Active TUI Protection Modal" width="100%"/>

---

## 🚀 Usage

Launch the interactive dashboard:

```bash
heimdall
```

### 🔍 Startup Filters
You can restrict the view to specific targets using command-line arguments:

```bash
# Filter by Port
heimdall --port 80

# Filter by PID
heimdall --pid 1234

# Filter by User
heimdall --user root

# Combine filters (e.g. root processes on port 443)
heimdall --port 443 --user root
```

## 🛠 Action Center (Interactive Operations)

Press `a` from the main screen to open the Action Center modal — a compact two-column modal grouping common operational actions for ports and processes.

UI / behavior highlights
- Monospace rendering inside curses; bordered window uses curses box().
- Padding: 2 spaces internal; text kept away from borders.
- Highlighting: reverse + bold for flash feedback (150–200ms) when a key is pressed.
- Single-key control: press the shown single-letter key (e.g., `b`) — no Enter or mouse required.
- ESC closes the topmost modal; each modal closes independently. When the modal stack is empty the main screen is redrawn (same effect as pressing `r`).
- All actions run inside the same curses process and provide immediate feedback.

Action Center layout (icons mirror the UI)
- Left column — 🌐 PORT OPERATIONS
  - 🚫  [b] Block IP
  - 💥  [k] Kill Connections
  - 🚦  [l] Connection Limit (planned)
- Right column — 🧠 PROCESS OPERATIONS
  - ⚡  [h] Reload (SIGHUP)
  - 💀  [9] Force Kill (SIGKILL)
  - 🌳  [t] Force Kill Tree (Nuclear Kill)
  - ⏸  [p] Pause Process (Tree-Aware)
  - ▶  [c] Continue Process (Tree-Aware)
  - 🔄  [r] Restart Service
  - ⚖️  [n] Renice (Priority)
  - ☠  [o] Adjust OOM Score
  - 🐞  [d] Debug Dump

## 🚫 Block IP — details

Invoked from Action Center via `[b]`:

- Two ways to choose an IP:
  1. Select from "Top connections" list (single-key 1..8). Selection flashes briefly and executes immediately.
  2. Manual entry: press `m` to start manual input, type the IP (digits, `.` for IPv4, `:` and hex for IPv6 allowed), Backspace supported, press `x` to execute.
- Validation:
  - Uses Python's `ipaddress` module for final validation before applying rules.
  - Textual length limits applied (reasonble max for IPv4/IPv6) to reject obviously invalid submissions.
- Execution:
  - Blocks via iptables (sudo) using a DROP rule limited to the selected port.
  - The UI updates a local cache of blocked IPs and shows that list inside the modal under "⛔ Blocked IPs".
  - After a successful block the application requests a full refresh (same behavior as pressing `r`) so the main view reflects changes immediately.
- Safety notes:
  - Blocking requires sudo and iptables — ensure appropriate privileges.
  - Actions are immediate and affect live traffic; use with care.

## 💥 Kill Connections — details

Invoked from Action Center via `[k]`:

- Lists all active ESTABLISHED connections for the selected port (up to 9 connections shown for single-key selection)
- Each connection shows: protocol (TCP/UDP), local address:port, and remote address:port
- Selection:
  - Press a number key (1-9) to select and kill the corresponding connection
  - Selected connection flashes briefly before termination
  - Press ESC to cancel without killing any connection
- Execution:
  - Primary method: Uses `sudo ss -K` to forcefully terminate the TCP connection
  - Fallback method: If `ss -K` fails, attempts to use `conntrack -D` to drop the connection from the connection tracking table
  - After successful termination, the UI automatically refreshes to reflect changes
- Use cases:
  - Terminate suspicious or unwanted connections
  - Free up connection slots when debugging connection limits
  - Quickly disconnect specific clients without affecting other connections
- Safety notes:
  - Requires sudo privileges for `ss -K` or `conntrack` commands
  - Connection termination is immediate and forceful (similar to TCP RST)
  - Use with caution in production environments
  - If connection count exceeds 9, only the first 9 are shown (consider using Block IP for bulk operations)

## 🚦 Connection Limit — details

Invoked from Action Center via `[l]`:

- **Purpose**: Limit concurrent TCP connections per IP to mitigate DoS attacks or ensure fair resource usage.
- **View Rules**: Lists existing iptables `connlimit` rules for the selected port.
- **Add Limit**: Quickly add predefined per-IP limits (5, 10, 25, 50, 100) using shortcut keys `[a-e]`.
  - Uses `iptables` with `connlimit` module.
  - Action is `REJECT` with `tcp-reset` (polite refusal).
- **Remove Limit**: Press `[x]` to remove all existing limit rules for the port.
- **Safety**:
  - Limits are enforced immediately via `sudo iptables`.
  - Non-persistent (cleared on reboot unless saved manually).


## 🔍 Interactive System Filter — details

Invoked from Main View via `[F]`:

- **Dynamic Filtering**: Instantly narrow down the live list without restarting the application.
- **Supported Fields**:
  - `[p] Port`: Filter by specific listener port (e.g., `80`, `443`).
  - `[i] PID`: Filter by specific Process ID.
  - `[u] User`: Filter by process owner (e.g., `root`, `www-data`).
- **Interactive Input**:
  - Press the field key (p, i, or u) to start typing.
  - Real-time buffer: See what you are typing before applying.
  - Press **ENTER** to save the value to the filter set.
  - Press **ESC** while typing to cancel the current field edit.
- **Apply & Clear**:
  - Press **ESC** (when not typing) to apply filters and return to the main view.
  - Press `[c]` to clear all active filters instantly.
- **Status Indicator**: When filters are active, a "🔍 Filter: ..." status line appears above the help bar in the main view.

## 🛡️ Heimdall Sentinel — details

Heimdall Sentinel is a **behavioral heuristic engine** that goes beyond simple process listing. It analyzes process metadata, command-line arguments, working directories, and process lineage to detect anomalies that traditional tools miss.

### Key Behavioral Detections:
- **☢️ Backdoor Patterns**: Detects Netcat (`nc`), `socat`, and other tools when they are used as active network listeners (e.g., `nc -l`).
- **🧪 Interpreter Bound**: Flags scripting languages (`python`, `bash`, `node`, `perl`) that are listening on ports without a known development context (Potential Reverse Shells).
- **🎭 Masquerading**: Identifies malicious processes that use innocent names (like `ls`, `ps`, or `date`) but are actually network services.
- **💀 Integrity Alerts**: Flags processes running from executables that have been deleted from the disk (a common malware persistence technique).
- **🌲 Lineage Analysis**: Detects suspicious process trees, such as network listeners spawned directly from a user shell instead of a proper system supervisor like `systemd`.
- **📂 Path & Privilege**: Alerts on processes running from world-writable directories (`/tmp`) or possessing unnecessary root privileges.

### Sentinel Intelligence Locations:
1. **Main View**: Visual icons (`☢️`, `💀`, `🧪`) appear next to process names for instant triage.
2. **Deep Inspection (i)**: Shows a prioritized list of security findings with human-readable explanations.
3. **Daemon Mode**: Monitors all *outbound* connections in real-time and suspends any process flagged by Sentinel until approved.
4. **Full System Dump (d)**: Includes a **Security Executive Summary** at the top of the report, grouping all critical threats for quick review.
## UI / Implementation notes

- Modal sizing is responsive to terminal size and has been widened to reduce text wrapping compared to earlier versions.
- Feedback messages are shown using a short non-blocking centered message overlay (no need to press an extra key to continue).
- The "Block IP" modal uses emoji/iconography to make options clearer and more visible in the TUI.

---

## ⚠️ Safety Notes (expanded)

- Destructive actions (stop, kill, firewall changes) require explicit keys; confirmation dialogs are used for stop operations.
- Blocking via iptables is immediate—this tool does not create persistent firewall rules across reboots.
- Non-root usage limits visibility; some operations require sudo.

---

## 🛡️ Risk & Security Indicators
 
Heimdall now proactively flags potential security issues directly in the main view using the **Sentinel Heuristic Engine**:
 
| Icon | Level | Meaning | Description |
|------|-------|---------|-------------|
| 🚩 | **DB** | **High Risk Service** | Known risky service (e.g., `FTP`, `Telnet`, `Redis`) from building-in database. |
| ☢️ | **CRIT** | **Backdoor Pattern** | `nc`, `socat` or similar tools actively waiting for inbound connections. |
| 🎭 | **CRIT** | **Masquerading** | Binary named like a common tool (`ls`, `ps`, `date`) but acting as a network listener. |
| 💀 | **CRIT** | **Deleted Binary** | The process is running from a deleted executable (Common malware behavior). |
| 🧪 | **HIGH** | **Script Listener** | An interpreter (`python`, `bash`, `node`) is listening without a known dev context. |
| 📂 | **HIGH** | **Suspicious CWD** | Process is working from world-writable directories like `/tmp` or `/dev/shm`. |
| 🌐 | **MED** | **Public Exposure** | Service is listening on `0.0.0.0` or `::` (Public) instead of localhost. |
| 🛡️ | **MED** | **Root Privilege** | Process belongs to the root user (Surface area risk). |
| 🌲 | **MED** | **Shell Lineage** | Process was spawned from a shell/terminal instead of a proper system service. |

*Example:* `👑 nc ☢️` means a Netcat process is running as root and has been flagged as a potential Backdoor.
 
---
 
## 🧩 Design Philosophy

- ❌ No reinvention of system tools
- ✅ Built on **native Linux introspection**
- 🔍 Read-only by default (except explicit stop/firewall actions)
- 🎯 Optimized for:
    - “Port already in use” debugging
    - Security inspection
    - DevOps / SRE diagnostics
    - Understanding legacy systems

---

## 📁 Project Structure
```bash
heimdall/
├── heimdall/            # 📦 Core Python Package
│   ├── __init__.py      # Main application logic & UI
│   ├── __main__.py      # Entry point (python -m heimdall)
│   ├── services.json    # Default service definitions database
│   └── services.sha256  # Integrity verification hash
├── screenshots/         # 📸 README screenshots & logo
├── run.py               # 🚀 Development wrapper script (run without installing)
├── release.sh           # 🤖 Automated build & release script
├── setup.py             # Python package configuration (pip/build)
├── MANIFEST.in          # Package file inclusion rules
├── debian/              # Debian packaging configuration
└── README.md
```

## 🛣️ Roadmap (Ideas)

- 🔎 Port search & filters
- 📤 JSON export
- 🧪 Parser unit tests
- 🍎 Partial macOS support
- 🔌 Plugin system

---

## 🚀 Release Management (For Maintainers)

Heimdall includes an automated `release.sh` script to manage versioning, builds, and publishing to PyPI, Debian, and GitHub.

### 📦 Prerequisites
```bash
# Install build and twine
pip install --upgrade build twine
```

### 🔑 Set Credentials
Before releasing, set your PyPI token:
```bash
export TWINE_USERNAME=__token__
export TWINE_PASSWORD=pypi-YOUR_TOKEN_HERE
```

### 🚢 Perform Release
The script automatically bumps versions in all metadata files, builds Wheel/Sdist/Deb, and uploads to PyPI.

```bash
# Bump patch (0.9.4 -> 0.9.5) and release to PyPI
./release.sh patch

# Bump minor (0.9.4 -> 1.0.0)
./release.sh minor

# Release to TestPyPI for verification
./release.sh patch --test
```

---

## 📄 License

MIT License

---

## 👤 Author

**Serkan Sunel**

---

---

> 🔌 **heimdall**  
> *See the whole picture — not just the port.*

## 🛠 Performance / Startup caching
- The TUI now eagerly preloads heavy data (witr output, connection lists, open-files and per-PID usage) for all discovered ports during the splash/startup phase. This means:
  - First launch may take a little longer (splash progress shows updates), but subsequent scrolling is instant because data is read from in-memory caches.
  - The UI operates on a read-only "snapshot" taken at startup — no heavy system commands are executed while you scroll. If you need fresh data, press `r` to refresh (re-takes the snapshot).
- You can tune caching TTL constants in the source (USAGE_TTL, FILES_TTL, PARSE_TTL, WITR_TTL, CONN_TTL) to balance freshness vs. UI responsiveness.
