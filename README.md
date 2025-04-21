# 🕵️♂️ BasicWebVulnScanner - Intelligent Web Vulnerability Scanner

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Async Ready](https://img.shields.io/badge/Asynchronous-✔-green?logo=asyncio)](https://docs.python.org/3/library/asyncio.html)

A high-performance web vulnerability scanner powered by Python, specializing in detecting **SQL Injection** and **XSS vulnerabilities**, featuring lightning-fast deep scanning with asynchronous technology.


## 🌟 Key Features
- **Dual Vulnerability Detection**: Precise identification of SQLi (`' OR '1'='1`) and XSS (`<script>alert(1)</script>`)
- **Smart Form Tracking**: Auto-parses HTML forms and tests all input fields
- **Asynchronous Deep Scan**: 5x faster than traditional scanners using `aiohttp` + `asyncio`
- **Visual Alerts**: Terminal color-coded warning system (Red/Yellow/Green)
- **Recursive Crawling**: Customizable scan depth (default: 2 levels)
- **Logging**: Auto-generates detailed scan reports (`vuln_scanner.log`)

## 🚀 Quick Start
### Requirements
- Python 3.8+
- Terminal with ANSI color support (Linux/macOS recommended or Windows Terminal)

### Installation
```bash
# Clone repository
git clone https://github.com/yourusername/VulnHunterAI.git
cd VulnHunterAI
```
 Install dependencies
```
pip install -r requirements.txt
```
Basic Usage
```
python vuln_scanner.py
# Enter target URL (include http/https)
```
Advanced Configuration (Code Customization)
```
# Customize scan depth (default: 2)
async def crawl_and_scan(start_url, depth=3)  # Modify here

# Extend detection rules (edit PAYLOADS dict)

PAYLOADS = {
    "SQL Injection": "' OR '1'='1",
    "XSS": "<img src=x onerror=alert(1)>",
    "New Vuln": "your_payload_here"  # Add new rules
}
```
📊 Sample Output
```
===  Terminal Scanner ===
Enter target URL (with http/https): https://example.com

[*] Scanning: https://example.com
[!] Potential SQL Injection found at https://example.com/login (Payload: ' OR '1'='1)
[OK] XSS test passed at https://example.com/contact
[*] Scanning: https://example.com/about
[OK] SQL Injection test passed at https://example.com/about
```
## ⚠️ Disclaimer

BasicVulnWebScanner is intended for ethical security testing only. Always obtain explicit permission from website owners before scanning their sites. Unauthorized scanning may violate laws or terms of service.

## 🤝 Contribution Guide
We welcome:

New vulnerability templates (update PAYLOADS dict)

Async optimization proposals

False-positive/negative cases

Documentation improvements

## 📬 Contact

Have questions or suggestions? Open an issue 

Happy scanning! 🔍
