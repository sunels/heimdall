# 🚀 Heimdall v0.9.9: The Traffic Intelligence Update

**This release introduces major real-time capabilities to Heimdall, bringing a powerful new Live Traffic column and deep structural layout improvements** — all while maintaining extreme performance with 0 blockings in the TUI!

### ✨ What's New
- **📡 Live Traffic Column (Background Polled):** 
  - Real-time network activity (Read/Write Bytes) is now integrated directly into the main table as an ASCII spark bar (`███████░░░` / `3.2M/s`).
  - **Tree-Aware I/O & UDP Tracking:** Uses deeper kernel I/O metrics (`/proc/pid/io`) alongside active connections to reliably track all activity — easily detecting heavy UDP tasks like high-res YouTube video streams, BitTorrent, and QUIC connections which often evaded traditional port-state polling.
  - **Sentinel Integration:** If Heimdall Sentinel finds a CRITICAL risk factor and it matches very high traffic flow simultaneously, the table row will actively *blink* to immediately warn you!
  - **Zero UI Blocking:** Powered by an intelligent background thread and a thread-safe caching system (`_traffic_poller_thread`). Your interactive inputs, scrolls, and animations remain instantly responsive.

- **📊 Wider Intelligence Panels:** 
  - Following user feedback, the *Open Files* panel has been dynamically widened and the overall horizontal real estate scaling has been perfected to give complete visibility to process paths, while fitting the newly injected 20-character Traffic column seamlessly.

- **📸 Updated Visual Assets:** 
  - `README.md` and `screenshots/` have been updated with the brand new UI look and documentation tags regarding the Live Traffic tracking.

### 🐛 Under the Hood
- Overhauled main grid dimensions for adaptive resizing without line cut-offs.
- Improved resource cleanup for phantom threads and short-lived background sockets during auto-scanning.

*Enjoy unparalleled visibility with Heimdall!* 🛡️
