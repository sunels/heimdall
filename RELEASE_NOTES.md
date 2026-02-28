## 🌐 Outbound Connections Modal & Real-time Traffic Analysis (v1.0.5)

This update introduces a major new feature: the **Outbound Connections Modal**, providing deep visibility into every external network connection originating from your system.

### **Key Features**
- **Unified Monitor (o)**: A high-density dashboard showing process, remote IP/Port, protocol, data transfer (Sent/Recv), and connection duration.
- **Ghost Connection Tracking**: Short-lived connections (like REST API calls) are captured and held in the list for 20 seconds after they close, marked as `[CLOSED]`.
- **Intelligent Risk Scoring**: Every outbound connection is automatically audited by the **Sentinel** engine to identify suspicious destinations or behavior.
- **Freeze/Pause (Space)**: Instantly freeze the live list to analyze a specific connection without rows jumping around.
- **Real-time Traffic Tail (t)**: Launch a dedicated sub-window to view raw packet data via `tcpdump`. Optimized with unbuffered streaming and clean-view heuristics.
- **File Tail (f)**: Instantly follow any file (logs, configs) owned by the process associated with a connection.

### **UI & Performance Enhancements**
- **Aligned Risk Column**: Fixed visual alignment for risk icons across all terminal widths.
- **Optimized Polling**: Reduced default outbound refresh interval to 3s for better responsiveness.
- **Noise Reduction**: Added intelligent filtering to the Traffic Tail view to minimize TCP/IP header noise while retaining core payloads.
- **Waiting Indicators**: Added "Capture is active" notifications to ensure users know the system is working during slow traffic.

### **Screenshots Added**
- 📸 `pp-25.png`: Outbound Connections Modal overview.
- 📸 `pp-26.png`: Real-time Traffic Tail analysis in action.
