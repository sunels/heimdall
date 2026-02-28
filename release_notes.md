## 🌐 Outbound Connections Modal - Zero-Loss Traffic Tail (v1.0.6)

This update drastically improves the reliability and performance of the Outbound Connections features.

### **✨ Major Enhancements (v1.0.6)**
- **OS-Level File Buffering for Tail Traffic**: The `Tail Traffic (t)` feature has been re-architected. Instead of Python-level threading, packet data is now streamed directly to an OS file buffer and read using high-speed `seek()` operations. This ensures **zero packet loss** and **terminal-grade performance** even under high load.
- **Smart Data Truncation**: UI şimdi dosyanın son 32KB'lık kısmını okur, böylece bellek kullanımı optimize edilirken canlı akış hızı korunur.
- **Improved UI Freeze**: Use **Space** to instantly lock the Outbound list, allowing for easier analysis of selected processes without row displacement.

### **🚀 Core Outbound Features (v1.0.5 Recap)**
- **Unified Monitor (o)**: Detailed external traffic dashboard (Process, Remote IP:Port, Protocol, Sent/Recv, Duration).
- **Ghost Connection Persistence**: Brief outbound connections (like REST API bursts) remain visible for 20s as `[CLOSED]`.
- **Integrated Sentinel Risk Audit**: Real-time behavioral risk scoring for every destination.
- **Direct Actions**: Kill connections, stop processes, or block IPs/Ports directly from the modal.

### **📸 New Screenshots**
- 📸 `pp-25.png`: Outbound Connections Modal overview.
- 📸 `pp-26.png`: Real-time Traffic Tail analysis in action.
