# Modbus TCP Communication & Anomaly Detection Visualizer

An interactive, browser-based OT/ICS network security visualizer built for teaching, demonstrating, and evaluating Modbus TCP industrial protocol communication and intrusion detection system (IDS) anomaly detection.

[![Launch Live Prototype](https://img.shields.io/badge/🚀%20LAUNCH-LIVE%20PROTOTYPE-emerald?style=for-the-badge&logo=googlechrome)](https://jamila131623-art.github.io/Modbus-Based-Monitoring-System/)
[![GitHub Pages](https://img.shields.io/badge/🌐%20GITHUB%20PAGES-OFFICIAL%20SITE-cyan?style=for-the-badge&logo=github)](https://jamila131623-art.github.io/Modbus-Based-Monitoring-System/)
[![Zero Build Step](https://img.shields.io/badge/Zero%20Build-HTML5%2FJS-blue?style=for-the-badge)](file:///c:/Users/User/Desktop/modbus/index.html)

---

### 🌐 [Click Here to Open Live Prototype in Browser](https://jamila131623-art.github.io/Modbus-Based-Monitoring-System/)

---

## 🛠 Features Overview

- **Interactive Topology Map (Canvas Animated)**:
  - **HMI SCADA Master** (`10.0.0.10`) polling industrial slaves.
  - **Ethernet Switch** with flashing port activity LEDs.
  - **3 Industrial PLC Slaves**:
    - **Unit 01 (`10.0.0.11`)**: Safety PLC (Emergency Shutdown, Interlock Bypass, Sensors).
    - **Unit 02 (`10.0.0.12`)**: Motor VFD PLC (Motor Speed RPM, Current, Temperature, Torque).
    - **Unit 03 (`10.0.0.13`)**: Tank Level PLC (Level Liters, Inlet Pump, Outlet Valve).
  - **Rogue Attacker Node** (`192.168.1.99`): Inactive during baseline polling; animates in red dashed line during attack scenarios.

- **Real-Time Byte Inspector & MBAP/PDU Decoder**:
  - Color-coded hex blocks for MBAP Header (Transaction ID, Protocol ID, Length, Unit ID) and Modbus PDU payload (Function Code, Address, Data).
  - Interactive hover tooltips and dynamic byte explanations.

- **Protocol State Machine (FSM) Auditor**:
  - Live state strip tracking: `IDLE` → `REQ_SENT` → `AWAIT_RESP` → `COMPLETE`.
  - Catches duplicate transaction IDs, out-of-sequence writes, and spoofed IPs.

- **Attack Scenario Library (6 Pre-configured Demonstrations)**:
  1. **Unauthorized Write / FC Misuse** *(Rule-based)*: Overrides Safety Interlock Bypass (Reg 40004).
  2. **Illegal Function Code** *(Rule-based)*: Injects reserved FC `0x99`, returning Exception Code `01`.
  3. **Replay Attack** *(Protocol-state FSM)*: Re-injects sniffed TxID 200 out of sequence.
  4. **DoS Flooding Attack** *(ML-based)*: Floods target PLC with 18 packets in 2s, triggering `QUEUE FULL` CPU overload.
  5. **Reconnaissance / Sweep** *(ML-based)*: Rapid address & Unit ID scan across register banks.
  6. **MITM / Spoofed Source** *(Protocol-state FSM)*: Direct switch injection spoofing Master IP `10.0.0.10`.

- **Physical Process Telemetry Simulation**:
  - Closed-loop physical simulation of motor speed, current, thermal buildup, and water tank levels.
  - Automatic **Safety ESD Shutdown** trip if motor RPM exceeds 3000 RPM while interlock is armed.

---

## 📁 Repository Structure

```
modbus/
├── index.html           # Main SPA HTML markup & component layout
├── css/
│   └── style.css        # Modern OT dark dashboard styles & custom LED animations
├── js/
│   ├── modbus-engine.js # Modbus MBAP/PDU codec, FSM state tracker & physics loop
│   ├── attack-library.js# 6 Attack Scenario handlers & security detection definitions
│   └── app.js           # Canvas topology renderer, event logger & UI controls
└── README.md            # Project documentation & user guide
```

---

## 🚀 How to Run

Because the project is completely self-contained with no build steps or dependencies:

1. **Option A (Direct File)**:
   Double-click `index.html` or open `file:///c:/Users/User/Desktop/modbus/index.html` in any web browser.

2. **Option B (Local Web Server)**:
   ```bash
   python -m http.server 8000
   ```
   Open `http://localhost:8000` in your web browser.

---

## 🛡 Security Detection Layers

| Detection Layer | Trigger Mechanism | Example Scenario |
| :--- | :--- | :--- |
| **Rule-Based** | Strict protocol specification matching (Unallowed FCs, write boundaries, IP ACLs). | Unauthorized Write (FC 06 to Reg 40004), Illegal FC `0x99`. |
| **Protocol-State (FSM)** | Transaction state auditing (TxID sequence check, expectation of response). | Replay Attack, MITM Spoofed Source IP. |
| **ML-Based** | Frequency metrics & statistical scanning pattern thresholds. | DoS Request Flood, Reconnaissance Sweep. |

---

## 🎓 Capstone Project Citation & Credits

Designed for college capstone presentations on Industrial Control System (ICS) security, Modbus TCP intrusion detection, and SCADA anomaly monitoring.
