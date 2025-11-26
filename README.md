<h1 align="center">
  <br>
  <a href="https://github.com/DeftonesL/Reconpy">
    <img src="https://img.shields.io/badge/Reconpy-v2.2-00ff41?style=for-the-badge&logo=appveyor" alt="Reconpy">
  </a>
</h1>

<h4 align="center">🚀 The Next-Generation Automated Reconnaissance Framework.</h4>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-workflow">Workflow</a> •
  <a href="#-disclaimer">Disclaimer</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=flat-square">
  <img src="https://img.shields.io/badge/Maintenance-Active-success?style=flat-square">
</p>

---

## 📖 Overview

**Reconpy** is an intelligent, automated reconnaissance tool built for Penetration Testers and Bug Bounty Hunters. It automates the boring stuff (subdomain enumeration, filtering, live probing) and moves directly to vulnerability scanning using a smart workflow.

It features a **Rich CLI**, **Smart WAF Detection**, **Discord Integration**, and **HTML Reporting**.

## ✨ Features

* **🎨 Rich UI:** Beautiful console output with progress bars and spinners using `Rich` library.
* **🧠 Smart WAF Detection:** Detects Cloudflare, Akamai, and Sucuri automatically and adjusts scan speed to avoid IP bans.
* **🔔 Discord Alerts:** Sends real-time notifications to your Discord channel when vulnerabilities are found.
* **📊 HTML Reporting:** Generates a clean HTML dashboard with all findings.
* **⚡ Speed Control:** Full control over threads and rate limits.
* **📂 Flexible Input:** Supports single targets (`-t`) or list of targets (`-l`).
* **🛡️ Tool Chaining:** seamlessly integrates `Subfinder`, `Assetfinder`, `Httpx`, and `Nuclei`.

---

## 🛠️ Installation

### 1. Clone the Repository
<h1 align="center">
  <br>
  <a href="https://github.com/DeftonesL/Reconpy">
    <img src="https://img.shields.io/badge/Reconpy-v2.2-00ff41?style=for-the-badge&logo=appveyor" alt="Reconpy">
  </a>
</h1>

<h4 align="center">🚀 The Next-Generation Automated Reconnaissance Framework.</h4>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-workflow">Workflow</a> •
  <a href="#-disclaimer">Disclaimer</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=flat-square">
  <img src="https://img.shields.io/badge/Maintenance-Active-success?style=flat-square">
</p>

---

## 📖 Overview

**Reconpy** is an intelligent, automated reconnaissance tool built for Penetration Testers and Bug Bounty Hunters. It automates the boring stuff (subdomain enumeration, filtering, live probing) and moves directly to vulnerability scanning using a smart workflow.

It features a **Rich CLI**, **Smart WAF Detection**, **Discord Integration**, and **HTML Reporting**.

## ✨ Features

* **🎨 Rich UI:** Beautiful console output with progress bars and spinners using `Rich` library.
* **🧠 Smart WAF Detection:** Detects Cloudflare, Akamai, and Sucuri automatically and adjusts scan speed to avoid IP bans.
* **🔔 Discord Alerts:** Sends real-time notifications to your Discord channel when vulnerabilities are found.
* **📊 HTML Reporting:** Generates a clean HTML dashboard with all findings.
* **⚡ Speed Control:** Full control over threads and rate limits.
* **📂 Flexible Input:** Supports single targets (`-t`) or list of targets (`-l`).
* **🛡️ Tool Chaining:** seamlessly integrates `Subfinder`, `Assetfinder`, `Httpx`, and `Nuclei`.

---

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone [https://github.com/DeftonesL/Reconpy.git](https://github.com/DeftonesL/Reconpy.git)
cd Reconpy
```
### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```
### 3. Install External Tools (The Engine) 
ApexRecon requires the following tools to be installed and available in your PATH:

- Subfinder

- Httpx

- Nuclei

- Assetfinder

### 4. Quick Install (using Go):
```bash
go install -v [github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest](https://github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)
go install -v [github.com/projectdiscovery/httpx/cmd/httpx@latest](https://github.com/projectdiscovery/httpx/cmd/httpx@latest)
go install -v [github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest](https://github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)
go install [github.com/tomnomnom/assetfinder@latest](https://github.com/tomnomnom/assetfinder@latest)
```

### 5. 💻 Usage
Basic Scan
Run a full reconnaissance on a single target:
```bash
python3 ApexRecon.py -t google.com
```

### Mass Scan (List of Targets)
Scan multiple companies from a text file:
```bash
python3 ApexRecon.py -l targets.txt
```

### Discord Alerts 🔔
Send notifications to your Discord webhook:
```bash
python3 ApexRecon.py -t tesla.com -w "[https://discord.com/api/webhooks/YOUR_WEBHOOK_URL](https://discord.com/api/webhooks/YOUR_WEBHOOK_URL)"
```

### High Performance Mode ⚡
Increase threads and rate limits (Use with caution):
```bash
python3 ApexRecon.py -t yahoo.com --threads 100 --rate-limit 300
```
### Debug Mode
Show raw output from underlying tools:
```bash
python3 ApexRecon.py -t target.com -v
```
### 🔄 Workflow
Setup: Creates organized directories for the target.

1. WAF Check: Checks if the target is behind a firewall (Cloudflare/Akamai).

2. Discovery: Harvests subdomains using Subfinder and Assetfinder.

3. Probing: Filters live hosts using Httpx.

4. Scanning: Scans live hosts for critical vulnerabilities using Nuclei.

5. Reporting: Generates HTML report and sends Discord alerts.

### ⚠️ Disclaimer
This tool is developed for educational purposes and authorized security testing only.

- Do not scan networks you do not own or have explicit permission to test.

- The author is not responsible for any misuse of this tool.

### 👨‍💻 Author : Saleh


- Role: Penetration Tester & Developer

- GitHub: DeftonesL

 ### 🌟 Show Support
If you find this tool useful, please give it a star on GitHub
