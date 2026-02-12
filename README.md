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
- 💥 **Kill Connections** operation implemented (Action Center → Kill Connections): list and kill established connections for a port (sudo may be required)
- 🚫 **Block IP** operation (Action Center → Block IP): block a source IP for a port via iptables (sudo required)
- 🧩 Modal UX: monospace, standard curses box(), 2-space padding, reverse+bold highlights, single‑key selection, ESC to close each modal

---

It enables you to seamlessly navigate the full relationship between:

> **Open ports → owning processes → CPU & memory usage → firewall rules → files in use**

This eliminates the need to jump between multiple tools such as `ss`, `netstat`, `lsof`, `top`, or firewall utilities.

---

![heimdall logo](logo.png)

---

## Core Navigation

```text
portwitr
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
<img src="pp-1.png" alt="heimdall main view" width="100%"/>

---

### 🧾 Detail View — Deep Port & Process Inspection
<img src="pp-2.png" alt="heimdall detail view" width="100%"/>

---
### 🧾 Detail View — Actions Center (Modal)
<img src="pp-3.png" alt="heimdall detail view" width="100%"/>

---
### 🧾 Detail View — Block IP Modal
<img src="pp-4.png" alt="heimdall detail view" width="100%"/>

---
### 🧾 Detail View — Connection Limit Modal
<img src="pp-5.png" alt="heimdall connection limit" width="100%"/>

---
### 🧾 Color Palette — Happy eyes edition
<img src="pp-6.png" alt="heimdall color palette" width="100%"/>

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

## 🚀 Installation

### Option 1 – From .deb package (recommended for Debian/Ubuntu)

Download the latest `.deb` from [Releases](https://github.com/sunels/heimdall/releases):

```
# Direct download
wget https://github.com/sunels/heimdall/releases/download/v0.3.0/heimdall_0.3.0-1_all.deb

# Installation
    sudo dpkg -i heimdall_0.3.0-1_all.deb

    #If dependencies are missing (rare):

    sudo apt update
    sudo apt install -f

# Run:
    sudo heimdall
    
# or just
    heimdall
```
### Option 2 – From source

Ensure you have Python 3.6+ and `witr` installed and accessible in your PATH.

Then clone the repository and run:

``` 
    git clone https://github.com/sunels/heimdall.git
    cd heimdall
    chmod +x heimdall.py
    sudo cp heimdall.py /usr/local/bin/heimdall
    # or create symlink
    sudo ln -s $(pwd)/heimdall.py /usr/local/bin/heimdall
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
  - 💥  [k] Kill Connections — lists active ESTABLISHED connections (select 1..9 to kill)
  - 🚦  [l] Connection Limit (planned)
- Right column — 🧠 PROCESS OPERATIONS
  - ⚡  [h] Reload (SIGHUP)
  - 💀  [9] Force Kill (SIGKILL)
  - ⏸  [p] Pause Process
  - ▶  [c] Continue Process
  - 🐢  [n] Renice
  - 🔄  [r] Restart Service
  - ☠  [o] Adjust OOM Score
  - 🐞  [d] Debug Dump

## 🚫 Block IP — details

Invoked from Action Center via `[b]`:

- Two ways to choose an IP:
  1. Select from "Top connections" list (single-key 1..8). Selection flashes briefly and executes immediately.
  2. Manual entry: press `m` to start manual input, type the IP (digits, `.` for IPv4, `:` and hex for IPv6 allowed), Backspace supported, press `x` to execute.
- Validation:
  - Uses Python's `ipaddress` module for final validation before applying rules.
  - Textual length limits applied (reasonable max for IPv4/IPv6) to reject obviously invalid submissions.
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
├── heimdall.py
├── README.md
├── pp-1.png
└── pp-2.png
```

## 🛣️ Roadmap (Ideas)

- 🔎 Port search & filters
- 📤 JSON export
- 🧪 Parser unit tests
- 🍎 Partial macOS support
- 🔌 Plugin system

---

## 📄 License

MIT License

---

## 👤 Author

**Serkan Sunel**

---

> 🔌 **heimdall**  
> *See the whole picture — not just the port.*

## 🛠 Performance / Startup caching
- The TUI now eagerly preloads heavy data (witr output, connection lists, open-files and per-PID usage) for all discovered ports during the splash/startup phase. This means:
  - First launch may take a little longer (splash progress shows updates), but subsequent scrolling is instant because data is read from in-memory caches.
  - The UI operates on a read-only "snapshot" taken at startup — no heavy system commands are executed while you scroll. If you need fresh data, press `r` to refresh (re-takes the snapshot).
- You can tune caching TTL constants in the source (USAGE_TTL, FILES_TTL, PARSE_TTL, WITR_TTL, CONN_TTL) to balance freshness vs. UI responsiveness.
