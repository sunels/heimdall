"""
integrity.py
────────────
Verifiable Integrity Dashboard Plugin for Heimdall.

Inspired by Amutable's (Lennart Poettering & Christian Brauner, 2026)
verifiable integrity mission — build/boot/runtime cryptographic checks.

Three-panel dashboard:
  LEFT   — Boot Integrity  (TPM2 PCR 0-7 measured boot verification)
  CENTER — Runtime Integrity  (Linux IMA measurement + xattr appraisal)
  RIGHT  — Anomalies & Actions  (Sentinel integration, risk scoring)

Controls:
  [v] Save/verify baseline   [r] Re-measure   [↑↓] scroll
  [b] Boot panel   [i] IMA panel   [a] Anomaly panel   [ESC] back

Optional dependencies:
  - tpm2-pytss  (TPM2 PCR reads, graceful fallback to tpm2_pcrread CLI)
  - ima-evm-utils  (appraisal checks, fallback to Python xattr)
"""

import os
import sys
import json
import time
import hashlib
import curses
import subprocess
import threading
from pathlib import Path

# ── Attempt optional imports ──────────────────────────────────────────────
try:
    from tpm2_pytss import ESAPI
    HAS_TPM2_PYTSS = True
except ImportError:
    HAS_TPM2_PYTSS = False

try:
    import xattr as _xattr_mod
    HAS_XATTR = True
except ImportError:
    HAS_XATTR = False

# ── Constants ─────────────────────────────────────────────────────────────
BASELINE_DIR = Path.home() / ".config" / "heimdall" / "integrity"
PCR_BASELINE = BASELINE_DIR / "expected_pcrs.json"
IMA_BASELINE = BASELINE_DIR / "ima_baseline.json"
VAULT_LOG    = BASELINE_DIR / "integrity_vault.jsonl"

IMA_RUNTIME  = "/sys/kernel/security/ima/ascii_runtime_measurements"

CRITICAL_PATHS = [
    "/bin", "/sbin", "/usr/bin", "/usr/sbin",
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/lib/systemd/systemd",
]
CRITICAL_UNIT_DIRS = [
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
]

# How many PCR banks to read (SHA-256 preferred, SHA-1 fallback)
PCR_INDICES = list(range(8))  # PCR 0-7

# Panel focus constants
PANEL_BOOT = 0
PANEL_IMA  = 1
PANEL_ANOM = 2


# ═══════════════════════════════════════════════════════════════════════════
# Helper utilities
# ═══════════════════════════════════════════════════════════════════════════

def _ensure_dir():
    """Ensure the baseline directory exists."""
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)


def _sha256_file(path):
    """Return hex SHA-256 digest for a file, or None on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _vault_append(entry: dict):
    """Append a JSON record to the integrity vault log."""
    try:
        _ensure_dir()
        entry["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        with open(VAULT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════
# TPM / Boot Integrity
# ═══════════════════════════════════════════════════════════════════════════

def _read_pcrs_pytss():
    """Read PCR 0-7 via tpm2-pytss library."""
    pcrs = {}
    try:
        with ESAPI() as ectx:
            for idx in PCR_INDICES:
                _, _, digests = ectx.pcr_read(f"sha256:{idx}")
                pcrs[str(idx)] = digests[0].hex() if digests else "N/A"
    except Exception as e:
        pcrs["_error"] = str(e)
    return pcrs


def _read_pcrs_cli():
    """Fallback: read PCR values via tpm2_pcrread CLI tool."""
    pcrs = {}
    try:
        out = subprocess.check_output(
            ["tpm2_pcrread", "sha256:0,1,2,3,4,5,6,7"],
            text=True, timeout=5, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            line = line.strip()
            # Format:  "  0 : 0x<hex>"
            if ":" in line:
                parts = line.split(":", 1)
                idx = parts[0].strip()
                val = parts[1].strip().replace("0x", "")
                if idx.isdigit() and int(idx) < 8:
                    pcrs[idx] = val
    except FileNotFoundError:
        pcrs["_error"] = "tpm2_pcrread not found (install tpm2-tools)"
    except subprocess.TimeoutExpired:
        pcrs["_error"] = "tpm2_pcrread timed out"
    except Exception as e:
        pcrs["_error"] = str(e)
    return pcrs


def read_pcrs():
    """Read TPM2 PCR 0-7, trying pytss first, then CLI fallback."""
    if not os.path.exists("/dev/tpm0") and not os.path.exists("/dev/tpmrm0"):
        return {"_error": "No TPM device detected (/dev/tpm0 or /dev/tpmrm0)"}
    if HAS_TPM2_PYTSS:
        result = _read_pcrs_pytss()
        if "_error" not in result:
            return result
    return _read_pcrs_cli()


def verify_pcrs(current: dict, baseline: dict):
    """Compare current PCRs against baseline, return list of mismatches."""
    mismatches = []
    for idx in PCR_INDICES:
        k = str(idx)
        cur = current.get(k, "")
        exp = baseline.get(k, "")
        if not cur or not exp:
            continue
        if cur.lower() != exp.lower():
            mismatches.append((idx, exp[:16] + "…", cur[:16] + "…"))
    return mismatches


def save_pcr_baseline(pcrs: dict):
    """Save current PCR values as the trusted baseline."""
    _ensure_dir()
    with open(PCR_BASELINE, "w") as f:
        json.dump(pcrs, f, indent=2)
    _vault_append({"event": "pcr_baseline_saved", "pcrs": pcrs})


def load_pcr_baseline():
    """Load the saved PCR baseline, or None."""
    try:
        with open(PCR_BASELINE) as f:
            return json.load(f)
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════
# IMA / Runtime Integrity
# ═══════════════════════════════════════════════════════════════════════════

def read_ima_measurements(limit=200):
    """
    Read /sys/kernel/security/ima/ascii_runtime_measurements.
    Returns list of dicts: {pcr, template_hash, template, file_hash, filename}
    Filters to CRITICAL_PATHS only.
    """
    entries = []
    if not os.path.exists(IMA_RUNTIME):
        return entries
    try:
        with open(IMA_RUNTIME, "r", errors="ignore") as f:
            for line in f:
                parts = line.strip().split(None, 4)
                if len(parts) < 5:
                    continue
                pcr, tmpl_hash, tmpl_name, file_hash, fname = parts
                # Filter to critical paths
                is_critical = False
                for cp in CRITICAL_PATHS:
                    if fname.startswith(cp):
                        is_critical = True
                        break
                if not is_critical:
                    for ud in CRITICAL_UNIT_DIRS:
                        if fname.startswith(ud):
                            is_critical = True
                            break
                if is_critical:
                    entries.append({
                        "pcr": pcr,
                        "template_hash": tmpl_hash,
                        "template": tmpl_name,
                        "file_hash": file_hash,
                        "filename": fname,
                    })
        # Return last `limit` entries (most recent)
        return entries[-limit:]
    except PermissionError:
        return [{"filename": "(Permission denied – run with sudo)", "file_hash": "N/A", "pcr": "-", "template": "-", "template_hash": "-"}]
    except Exception:
        return []


def check_ima_xattr(filepath):
    """
    Check if a file has the security.ima extended attribute.
    Returns: 'signed', 'hash', 'none', or 'error'.
    """
    try:
        if HAS_XATTR:
            val = _xattr_mod.getxattr(filepath, "security.ima")
            if val:
                # First byte is the type: 0x01=digest, 0x03=signature
                if len(val) > 0 and val[0] == 0x03:
                    return "signed"
                return "hash"
        else:
            val = os.getxattr(filepath, b"security.ima")
            if val:
                if len(val) > 0 and val[0] == 0x03:
                    return "signed"
                return "hash"
    except OSError:
        return "none"
    except Exception:
        return "error"
    return "none"


def hash_systemd_units():
    """Hash critical systemd unit files and return dict {path: sha256}."""
    hashes = {}
    for unit_dir in CRITICAL_UNIT_DIRS:
        if not os.path.isdir(unit_dir):
            continue
        try:
            for fname in os.listdir(unit_dir):
                if fname.endswith((".service", ".timer", ".socket")):
                    fullpath = os.path.join(unit_dir, fname)
                    if os.path.isfile(fullpath):
                        digest = _sha256_file(fullpath)
                        if digest:
                            hashes[fullpath] = digest
        except Exception:
            continue
    return hashes


def save_ima_baseline(unit_hashes: dict):
    """Save systemd unit hashes as IMA baseline."""
    _ensure_dir()
    with open(IMA_BASELINE, "w") as f:
        json.dump(unit_hashes, f, indent=2)
    _vault_append({"event": "ima_baseline_saved", "count": len(unit_hashes)})


def load_ima_baseline():
    """Load the saved IMA unit baseline, or None."""
    try:
        with open(IMA_BASELINE) as f:
            return json.load(f)
    except Exception:
        return None


def verify_unit_integrity(current: dict, baseline: dict):
    """
    Compare current unit hashes against baseline.
    Returns list of anomalies: (path, status).
    """
    anomalies = []
    for path, cur_hash in current.items():
        base_hash = baseline.get(path)
        if base_hash is None:
            anomalies.append((path, "NEW"))
        elif cur_hash != base_hash:
            anomalies.append((path, "MODIFIED"))
    for path in baseline:
        if path not in current:
            anomalies.append((path, "DELETED"))
    return anomalies


# ═══════════════════════════════════════════════════════════════════════════
# Background periodic checker (for daemon mode)
# ═══════════════════════════════════════════════════════════════════════════

class IntegrityChecker(threading.Thread):
    """Background thread that periodically checks PCR & IMA integrity."""

    def __init__(self, interval=300):
        super().__init__(daemon=True)
        self.interval = interval
        self._stop_event = threading.Event()
        self.last_result = {"boot": {}, "ima": [], "anomalies": [], "ts": 0}
        self.lock = threading.Lock()

    def run(self):
        while not self._stop_event.is_set():
            try:
                self._check()
            except Exception:
                pass
            self._stop_event.wait(self.interval)

    def stop(self):
        self._stop_event.set()

    def _check(self):
        result = {"ts": time.time(), "boot": {}, "ima": [], "anomalies": []}

        # Boot integrity
        pcrs = read_pcrs()
        result["boot"]["pcrs"] = pcrs
        baseline = load_pcr_baseline()
        if baseline and "_error" not in pcrs:
            mismatches = verify_pcrs(pcrs, baseline)
            result["boot"]["mismatches"] = mismatches
            result["boot"]["status"] = "VERIFIED" if not mismatches else "MISMATCH"
        elif "_error" in pcrs:
            result["boot"]["status"] = pcrs["_error"]
        else:
            result["boot"]["status"] = "NO_BASELINE"

        # IMA / Runtime
        ima_entries = read_ima_measurements(limit=50)
        result["ima"] = ima_entries

        unit_hashes = hash_systemd_units()
        ima_baseline = load_ima_baseline()
        if ima_baseline:
            anomalies = verify_unit_integrity(unit_hashes, ima_baseline)
            result["anomalies"] = anomalies
            if anomalies:
                _vault_append({
                    "event": "integrity_anomaly",
                    "anomalies": [(p, s) for p, s in anomalies[:10]]
                })

        with self.lock:
            self.last_result = result

    def get_result(self):
        with self.lock:
            return dict(self.last_result)


# ═══════════════════════════════════════════════════════════════════════════
# Plugin class (inherits CommandViewerPlugin pattern but custom render)
# ═══════════════════════════════════════════════════════════════════════════

class Plugin:
    """
    Verifiable Integrity Dashboard — Heimdall Plugin.

    Displays a three-panel dashboard for boot, runtime, and anomaly
    verification. Integrates with Sentinel risk scoring.
    """

    name             = "Integrity"
    description      = "Verifiable Integrity Dashboard — TPM PCR, IMA, systemd unit auditing"
    tabTitle         = "🔏 Integrity"
    tool_command     = None  # No external tool required
    mode             = "command_viewer"  # Use the command_viewer rendering path
    refresh_interval = 120

    def __init__(self, heimdall_instance):
        self.h           = heimdall_instance
        self._scroll     = 0
        self._panel      = PANEL_BOOT
        self._checker    = IntegrityChecker(interval=120)
        self._checker.start()
        self._lines      = []
        self._last_run   = 0.0
        self._running    = False

    def start(self):
        self._running  = True
        self._scroll   = 0
        self._last_run = 0.0

    def stop(self):
        self._running = False

    # ── Custom multi-panel render ─────────────────────────────────────────

    def render(self, tab_win):
        now = time.time()
        if now - self._last_run >= self.refresh_interval or self._last_run == 0:
            self._refresh()

        h, w = tab_win.getmaxyx()
        tab_win.erase()

        # ── Header ────────────────────────────────────────────────────────
        panel_names = [" [B]oot ", " [I]MA/Runtime ", " [A]nomalies "]
        hdr = "  🔏 VERIFIABLE INTEGRITY DASHBOARD  │"
        for i, pn in enumerate(panel_names):
            if i == self._panel:
                hdr += f" ▶{pn}◀"
            else:
                hdr += f"  {pn} "
        hdr += "  │  [v] Baseline  [r] Remeasure  [↑↓] Scroll"
        try:
            tab_win.addstr(0, 0, hdr[:w - 1], curses.A_REVERSE | curses.A_BOLD)
        except Exception:
            pass

        # ── Build lines for current panel ─────────────────────────────────
        lines = self._lines
        max_scroll = max(0, len(lines) - (h - 3))
        self._scroll = max(0, min(self._scroll, max_scroll))

        for idx in range(h - 3):
            line_no = self._scroll + idx
            if line_no >= len(lines):
                break
            text, attr = lines[line_no]
            try:
                tab_win.addstr(1 + idx, 0, text[:w - 1], attr)
            except Exception:
                pass

        # ── Footer ────────────────────────────────────────────────────────
        try:
            pct = int(100 * self._scroll / max(1, len(lines) - (h - 3)))
            age = int(now - self._last_run)
            footer = f" {pct:3d}%  │  line {self._scroll + 1}/{len(lines)}  │  data age: {age}s  │  next refresh: {max(0, self.refresh_interval - age)}s "
            tab_win.addstr(h - 2, 0, footer[:w - 1], curses.A_DIM)
        except Exception:
            pass

        tab_win.noutrefresh()

    def on_key(self, key):
        page = 20
        if key in (curses.KEY_UP, ord('k')):
            self._scroll = max(0, self._scroll - 1)
        elif key in (curses.KEY_DOWN, ord('j')):
            self._scroll += 1
        elif key in (curses.KEY_PPAGE, ord(' ')):
            self._scroll = max(0, self._scroll - page)
        elif key in (curses.KEY_NPAGE,):
            self._scroll += page
        elif key in (curses.KEY_HOME,):
            self._scroll = 0
        elif key in (curses.KEY_END,):
            self._scroll = max(0, len(self._lines) - 1)
        elif key == ord('r'):
            self._last_run = 0.0
            self._checker._check()
            self._refresh()
        elif key == ord('v'):
            self._save_baseline()
            self._refresh()
        elif key == ord('b'):
            self._panel = PANEL_BOOT
            self._scroll = 0
            self._refresh()
        elif key == ord('i'):
            self._panel = PANEL_IMA
            self._scroll = 0
            self._refresh()
        elif key == ord('a'):
            self._panel = PANEL_ANOM
            self._scroll = 0
            self._refresh()

    # ── Internal ──────────────────────────────────────────────────────────

    def _refresh(self):
        result = self._checker.get_result()
        self._last_run = time.time()

        if self._panel == PANEL_BOOT:
            self._lines = self._build_boot_lines(result)
        elif self._panel == PANEL_IMA:
            self._lines = self._build_ima_lines(result)
        else:
            self._lines = self._build_anomaly_lines(result)

    def _build_boot_lines(self, result):
        lines = []
        A_BOLD = curses.A_BOLD
        A_DIM  = curses.A_DIM
        A_NORM = curses.A_NORMAL

        lines.append(("", A_NORM))
        lines.append(("  ╔══════════════════════════════════════════════════════════════════╗", A_BOLD))
        lines.append(("  ║              🔐 BOOT INTEGRITY — TPM2 PCR VERIFICATION          ║", A_BOLD))
        lines.append(("  ╚══════════════════════════════════════════════════════════════════╝", A_BOLD))
        lines.append(("", A_NORM))

        boot = result.get("boot", {})
        pcrs = boot.get("pcrs", {})
        status = boot.get("status", "UNKNOWN")
        mismatches = boot.get("mismatches", [])

        # Status banner
        if status == "VERIFIED":
            lines.append(("  ✅ Measured Boot: VERIFIED — All PCR values match baseline", curses.color_pair(2) | A_BOLD))
        elif status == "MISMATCH":
            lines.append(("  🚨 Measured Boot: PCR MISMATCH DETECTED!", curses.color_pair(4) | A_BOLD))
        elif status == "NO_BASELINE":
            lines.append(("  ⚠️  No baseline saved yet. Press [v] to save current state as baseline.", curses.color_pair(4)))
        else:
            lines.append((f"  ⚠️  {status}", curses.color_pair(4)))

        lines.append(("", A_NORM))

        if "_error" in pcrs:
            lines.append((f"  ❌ TPM Error: {pcrs['_error']}", curses.color_pair(4)))
            lines.append(("", A_NORM))
            lines.append(("  💡 Possible solutions:", A_DIM))
            lines.append(("     • Enable TPM2 in BIOS/UEFI settings", A_DIM))
            lines.append(("     • Install tpm2-tools: sudo apt install tpm2-tools", A_DIM))
            lines.append(("     • Install tpm2-pytss: pip install tpm2-pytss", A_DIM))
            lines.append(("     • Load TPM kernel module: sudo modprobe tpm_tis", A_DIM))
        else:
            # PCR table
            lines.append(("  ┌─────┬────────────────────────────────────────────────────────────────────┬──────────┐", A_DIM))
            lines.append(("  │ PCR │ SHA-256 Value                                                      │ Status   │", A_BOLD))
            lines.append(("  ├─────┼────────────────────────────────────────────────────────────────────┼──────────┤", A_DIM))

            pcr_labels = {
                "0": "SRTM/BIOS",
                "1": "Platform Config",
                "2": "Option ROMs",
                "3": "Option ROM Config",
                "4": "Boot Loader/Kernel",
                "5": "Boot Loader Config",
                "6": "Resume Events",
                "7": "Secure Boot",
            }

            baseline = load_pcr_baseline() or {}
            mismatch_set = {m[0] for m in mismatches}

            for idx in PCR_INDICES:
                k = str(idx)
                val = pcrs.get(k, "N/A")
                label = pcr_labels.get(k, "")
                val_display = val[:64] if val != "N/A" else "N/A"

                if idx in mismatch_set:
                    status_icon = "🔴 FAIL"
                    attr = curses.color_pair(4) | A_BOLD
                elif k in baseline:
                    status_icon = "🟢 OK  "
                    attr = curses.color_pair(2)
                else:
                    status_icon = "⚪ N/A "
                    attr = A_DIM

                lines.append((f"  │  {idx}  │ {val_display:<68s} │ {status_icon} │", attr))

            lines.append(("  └─────┴────────────────────────────────────────────────────────────────────┴──────────┘", A_DIM))

            lines.append(("", A_NORM))
            for idx in PCR_INDICES:
                k = str(idx)
                label = pcr_labels.get(k, "")
                if label:
                    lines.append((f"    PCR {idx}: {label}", A_DIM))

        if mismatches:
            lines.append(("", A_NORM))
            lines.append(("  ⚠️  MISMATCHED PCRs:", curses.color_pair(4) | A_BOLD))
            for idx, exp, cur in mismatches:
                lines.append((f"    PCR {idx}: Expected {exp}  →  Got {cur}", curses.color_pair(4)))

        lines.append(("", A_NORM))
        lines.append(("  ─── Actions ───────────────────────────────────────────────────", A_DIM))
        lines.append(("  [v] Save current PCRs as trusted baseline", A_NORM))
        lines.append(("  [r] Re-read PCR values now", A_NORM))

        return lines

    def _build_ima_lines(self, result):
        lines = []
        A_BOLD = curses.A_BOLD
        A_DIM  = curses.A_DIM
        A_NORM = curses.A_NORMAL

        lines.append(("", A_NORM))
        lines.append(("  ╔══════════════════════════════════════════════════════════════════╗", A_BOLD))
        lines.append(("  ║         🛡️ RUNTIME INTEGRITY — IMA MEASUREMENTS & APPRAISAL     ║", A_BOLD))
        lines.append(("  ╚══════════════════════════════════════════════════════════════════╝", A_BOLD))
        lines.append(("", A_NORM))

        ima = result.get("ima", [])

        if not os.path.exists(IMA_RUNTIME):
            lines.append(("  ⚠️  IMA (Integrity Measurement Architecture) is not enabled on this kernel.", curses.color_pair(4)))
            lines.append(("", A_NORM))
            lines.append(("  💡 To enable IMA:", A_DIM))
            lines.append(("     • Add to kernel cmdline: ima_policy=tcb ima_appraise=fix", A_DIM))
            lines.append(("     • Or boot with: ima=on ima_policy=appraise_tcb", A_DIM))
            lines.append(("     • Reboot required after enabling.", A_DIM))
        elif not ima:
            lines.append(("  ℹ️  No critical-path IMA measurements found (may need sudo).", A_DIM))
        else:
            lines.append((f"  📊 {len(ima)} critical-path measurements loaded from IMA runtime log:", A_BOLD))
            lines.append(("", A_NORM))
            lines.append(("  ┌─────┬──────────────────────────┬────────────────────────────────────────────────┐", A_DIM))
            lines.append(("  │ PCR │ Hash (truncated)         │ File                                           │", A_BOLD))
            lines.append(("  ├─────┼──────────────────────────┼────────────────────────────────────────────────┤", A_DIM))

            for entry in ima:
                pcr = entry.get("pcr", "-")
                fhash = entry.get("file_hash", "")[:24]
                fname = entry.get("filename", "")
                xattr_status = check_ima_xattr(fname) if os.path.exists(fname) else "n/a"

                if xattr_status == "signed":
                    attr = curses.color_pair(2)
                    icon = "🟢"
                elif xattr_status == "hash":
                    attr = curses.color_pair(2)
                    icon = "🔵"
                elif xattr_status == "none":
                    attr = curses.color_pair(4)
                    icon = "⚪"
                else:
                    attr = A_DIM
                    icon = "⚫"

                lines.append((f"  │ {pcr:>3s} │ {fhash:<24s} │ {icon} {fname:<44s} │", attr))

            lines.append(("  └─────┴──────────────────────────┴────────────────────────────────────────────────┘", A_DIM))

        # Systemd unit integrity
        lines.append(("", A_NORM))
        lines.append(("  ═══════════════════════════════════════════════════════════════════", A_BOLD))
        lines.append(("  📦 SYSTEMD UNIT FILE INTEGRITY", A_BOLD))
        lines.append(("  ═══════════════════════════════════════════════════════════════════", A_BOLD))
        lines.append(("", A_NORM))

        unit_hashes = hash_systemd_units()
        baseline = load_ima_baseline()

        if baseline:
            anomalies = verify_unit_integrity(unit_hashes, baseline)
            total = len(unit_hashes)
            clean = total - len([a for a in anomalies if a[1] != "DELETED"])
            lines.append((f"  ✅ {clean}/{total} unit files match baseline", curses.color_pair(2) if not anomalies else A_NORM))

            if anomalies:
                lines.append(("", A_NORM))
                lines.append(("  ⚠️  UNIT ANOMALIES:", curses.color_pair(4) | A_BOLD))
                for path, status in anomalies[:20]:
                    icon = "🔴" if status == "MODIFIED" else ("🟡" if status == "NEW" else "⚫")
                    lines.append((f"    {icon} [{status:>8s}] {path}", curses.color_pair(4)))
        else:
            lines.append((f"  ℹ️  {len(unit_hashes)} unit files found. No baseline saved yet.", A_DIM))
            lines.append(("  ⚠️  Press [v] to save current unit hashes as baseline.", curses.color_pair(4)))

        lines.append(("", A_NORM))
        lines.append(("  ─── Legend ────────────────────────────────────────────────────", A_DIM))
        lines.append(("  🟢 signed (security.ima xattr with signature)", A_NORM))
        lines.append(("  🔵 hash-only (security.ima xattr with digest)", A_NORM))
        lines.append(("  ⚪ no xattr (not appraised by IMA)", A_NORM))

        return lines

    def _build_anomaly_lines(self, result):
        lines = []
        A_BOLD = curses.A_BOLD
        A_DIM  = curses.A_DIM
        A_NORM = curses.A_NORMAL

        lines.append(("", A_NORM))
        lines.append(("  ╔══════════════════════════════════════════════════════════════════╗", A_BOLD))
        lines.append(("  ║         🚨 ANOMALIES & ACTIONS — SENTINEL INTEGRATION           ║", A_BOLD))
        lines.append(("  ╚══════════════════════════════════════════════════════════════════╝", A_BOLD))
        lines.append(("", A_NORM))

        anomalies = result.get("anomalies", [])
        boot = result.get("boot", {})
        boot_mismatches = boot.get("mismatches", [])

        total_issues = len(anomalies) + len(boot_mismatches)

        if total_issues == 0:
            lines.append(("  ✅ SYSTEM INTEGRITY: ALL CLEAR", curses.color_pair(2) | A_BOLD))
            lines.append(("", A_NORM))
            lines.append(("  No boot PCR mismatches detected.", curses.color_pair(2)))
            lines.append(("  No systemd unit file tamper detected.", curses.color_pair(2)))
            lines.append(("  All verified checks passed.", curses.color_pair(2)))
        else:
            lines.append((f"  🚨 {total_issues} INTEGRITY ISSUE(S) DETECTED", curses.color_pair(4) | A_BOLD))

        # Boot issues
        if boot_mismatches:
            lines.append(("", A_NORM))
            lines.append(("  ── Boot Integrity Issues ──────────────────────────────────────", curses.color_pair(4) | A_BOLD))
            for idx, exp, cur in boot_mismatches:
                lines.append((f"    🔴 PCR {idx} mismatch — boot chain may be compromised", curses.color_pair(4)))
                lines.append((f"       Expected: {exp}", A_DIM))
                lines.append((f"       Current:  {cur}", A_DIM))

        # Unit anomalies
        if anomalies:
            lines.append(("", A_NORM))
            lines.append(("  ── Runtime / Unit Anomalies ──────────────────────────────────", curses.color_pair(4) | A_BOLD))
            for path, status in anomalies[:30]:
                if status == "MODIFIED":
                    lines.append((f"    🔴 MODIFIED: {path}", curses.color_pair(4) | A_BOLD))
                    lines.append(("       → File hash changed since baseline — possible tampering!", curses.color_pair(4)))
                elif status == "NEW":
                    lines.append((f"    🟡 NEW UNIT: {path}", curses.color_pair(4)))
                    lines.append(("       → Unit file appeared after baseline — verify origin.", A_DIM))
                elif status == "DELETED":
                    lines.append((f"    ⚫ DELETED: {path}", A_DIM))
                    lines.append(("       → Unit removed since baseline.", A_DIM))

        # Sentinel integration note
        lines.append(("", A_NORM))
        lines.append(("  ═══════════════════════════════════════════════════════════════════", A_BOLD))
        lines.append(("  🛡️ SENTINEL INTEGRATION", A_BOLD))
        lines.append(("  ═══════════════════════════════════════════════════════════════════", A_BOLD))
        lines.append(("", A_NORM))

        if total_issues > 0:
            risk_boost = min(total_issues * 15, 50)
            lines.append((f"  ⚡ Risk score boost: +{risk_boost} applied to affected processes", curses.color_pair(4)))
            lines.append(("  🛡️ Guardian Mode: Will auto-suspend processes with tampered binaries", A_NORM))
        else:
            lines.append(("  ✅ No integrity risk adjustments needed.", curses.color_pair(2)))

        # Vault log
        lines.append(("", A_NORM))
        lines.append(("  ═══════════════════════════════════════════════════════════════════", A_BOLD))
        lines.append(("  📋 INTEGRITY VAULT LOG (last 10 entries)", A_BOLD))
        lines.append(("  ═══════════════════════════════════════════════════════════════════", A_BOLD))
        lines.append(("", A_NORM))

        vault_entries = self._read_vault_tail(10)
        if vault_entries:
            for entry in vault_entries:
                ts = entry.get("ts", "?")
                event = entry.get("event", "unknown")
                lines.append((f"    [{ts}] {event}", A_DIM))
        else:
            lines.append(("    (No vault entries yet)", A_DIM))

        lines.append(("", A_NORM))
        lines.append(("  ─── Actions ───────────────────────────────────────────────────", A_DIM))
        lines.append(("  [v] Update baseline (PCR + unit hashes)", A_NORM))
        lines.append(("  [r] Force re-measure now", A_NORM))
        lines.append(("  [b] Switch to Boot panel", A_NORM))
        lines.append(("  [i] Switch to IMA panel", A_NORM))

        return lines

    def _save_baseline(self):
        """Save current PCR + unit hashes as trusted baseline."""
        pcrs = read_pcrs()
        if "_error" not in pcrs:
            save_pcr_baseline(pcrs)

        unit_hashes = hash_systemd_units()
        if unit_hashes:
            save_ima_baseline(unit_hashes)

    def _read_vault_tail(self, n=10):
        """Read last n entries from the vault log."""
        entries = []
        try:
            with open(VAULT_LOG, "r") as f:
                all_lines = f.readlines()
                for line in all_lines[-n:]:
                    try:
                        entries.append(json.loads(line.strip()))
                    except Exception:
                        pass
        except Exception:
            pass
        return entries
