# 🛡️ Adaptive Ransomware Defense System
![GitHub last commit](https://img.shields.io/github/last-commit/jhapalizzz/adaptive-ransomware-defense)
![GitHub issues](https://img.shields.io/github/issues/jhapalizzz/adaptive-ransomware-defense)
![GitHub stars](https://img.shields.io/github/stars/jhapalizzz/adaptive-ransomware-defense?style=social)


A real-time, lightweight ransomware defense system that detects suspicious file behaviors, stops threats immediately, and recovers encrypted files — all with automation and minimal resource usage.

---

## 🧠 What It Does

- **Real-time Behavioral Monitoring**  
  Continuously observes file system events using `watchdog` to identify ransomware-like patterns — such as rapid file modifications or suspicious filenames/hashes.

- **Instant Threat Response**  
  Suspicious processes are automatically terminated on detection to prevent further damage.

- **Incremental Backup System**  
  Before any file is modified, the system creates a secure backup — ensuring clean recovery points without bloating storage.

- **Automated File Recovery**  
  Upon detection of ransomware behavior, original files are automatically restored from backup in real time.

- **Multi-Channel Alerting**  
  Sound alarms, pop-up warnings, and detailed logs notify the user as soon as an attack is detected.

- **Threat Feed Integration**  
  Uses a local feed of known malicious file hashes and suspicious filenames to enhance detection accuracy.

- **Robust Logging & Error Handling**  
  Every critical event and system decision is logged clearly, with proper handling to prevent crashes.

---

## 🎯 Simulation-Ready

To validate the system, a ransomware simulator script is included that:

- Targets a test directory.
- Renames files to mimic encryption (`locked_*.enc` format).
- Triggers real-time alerts, process kills, and automated recovery — demonstrating full workflow under realistic attack behavior.

---

> 💡 *Future Enhancements (Planned):*  
> AI-based anomaly detection, network isolation, cloud backup integration, web dashboard, Docker deployment.

---

## 📁 Repo Structure (Suggested)

adaptive-ransomware-defense/
│
├── monitor.py # Main detection + response script
├── ransomware_sim.py # Safe ransomware simulator
├── backup/ # Stores pre-modified file backups
├── logs/ # System logs
├── test_dir/ # Directory used for simulation testing
└── requirements.txt



---

## ⚙️ Tech Stack

- Python
- watchdog
- win10toast
- shutil / os / time
- Sound + GUI alerting (e.g., `winsound`, `ctypes`)
