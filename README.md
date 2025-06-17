# DNS Cache Malicious Domain Checker

A Python script for Windows systems that inspects the local DNS resolver cache and checks all resolved domains against multiple, up-to-date public threat intelligence blocklists.

> **Purpose:**  
> Quickly discover malicious or suspicious domains your system has resolved—no packets, no logs, just forensic blue-team automation.

---

## Features

- **Inspects local DNS cache** (using PowerShell for reliability)
- **Checks each domain against fresh threat intelligence feeds:**
  - [abuse.ch URLhaus](https://urlhaus.abuse.ch/)
  - [OpenPhish](https://openphish.com/)
  - [StevenBlack/hosts](https://github.com/StevenBlack/hosts)
- **Classifies domains:**
  - `[MALICIOUS]` (on blocklist)
  - `[KNOWN-GOOD]` (allow-list: Google, Microsoft, etc.)
  - `[UNSURE]` (not on either list—manual review suggested)
- **Color-coded, readable output**
- **No data leaves your machine. No privacy risks.**

---

## Requirements

- **Python 3.x**
- [`requests`](https://pypi.org/project/requests/) (`pip install requests`)
- **Windows 10/11** (PowerShell required, default on modern Windows)
- Internet connection (to fetch the latest blocklists)

---

## Installation

1. **Clone the repo or download the script.**
2. **Install dependencies:**
   ```bash
   pip install requests
