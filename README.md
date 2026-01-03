# 🔍 Nmap Scan Automation with Python

## 📌 Overview
This project demonstrates how **Nmap network scans** can be automated using Python.
It performs **SYN stealth scanning** with **service and version detection** and
generates a structured scan report.

The goal of this project is to showcase **network reconnaissance**, **security
assessment fundamentals**, and **Python automation** skills.

---

## 🛠 Tools & Technologies
- Nmap
- Python 3
- python-nmap
- Linux / Kali Linux

---

## ⚙️ Features
- Automated SYN scan (`-sS`)
- Service & version detection (`-sV`)
- Verbose scan execution
- Text-based report generation
- Error handling and logging

---

## 🚀 Installation

### 1️⃣ Install Nmap
```bash
sudo apt update
sudo apt install nmap
```
### 2️⃣ Install Python dependencies
```bash
pip install -r requirements.txt


```
## ▶️ Usage
```bash
sudo python3 nmap_automation.py <target_ip>
```


##📄 Output

The script generates a text-based scan report:
scan_report.txt

The report contains:
- Scan timestamp 
- Target IP and hostname
- Host state (up/down)
- Open ports and protocols
- Detected services and versions
- Nmap command executed
