# DNS Cache Malicious Domain Checker
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue)
![Python: 3.x](https://img.shields.io/badge/Python-3.x-3776AB)

A Python script for Windows systems that inspects the local DNS resolver cache via Powershell and checks all resolved domains against multiple, up-to-date public threat intelligence blocklists.

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
   ```bash
   git clone https://github.com/skull-ttl/dns-checker.git
   cd dns-checker
   ```
2. **Install dependencies:**
   ```bash
   pip install requests
   ```
3. **Run the script:**
   ```bash
   python dnscachechecker.py
   ```

---

## Example Output

Here’s what a typical run looks like:

```text
[*] Fetching URLhaus...
[*] Fetching OpenPhish...
[*] Fetching StevenBlack/hosts...
[*] Total unique malicious domains loaded: 249571
[*] Getting local DNS cache (via PowerShell)...
[*] Found 143 DNS cache entries.

[*] Top 20 most frequent DNS cache domains (categorized):
     [RED] = Malicious  [GREEN] = Known-Good  [YELLOW] = Unsure/Manual Check

www.jetbrains.com                               4 [UNSURE]
raw.githubusercontent.com                       4 [MALICIOUS]
desktop.githubusercontent.com                   4 [KNOWN-GOOD]
plugins.jetbrains.com                           4 [UNSURE]
oneocsp.microsoft.com                           3 [KNOWN-GOOD]

Summary: 1 malicious, 3 known-good, 16 unsure/manual check

[!!!] Malicious domains found in your DNS cache:
   raw.githubusercontent.com
   urlhaus.abuse.ch
```

---

## Legal

[INFO] Sources used for blocklists:
- https://urlhaus.abuse.ch/downloads/text/  
- https://openphish.com/feed.txt  
- https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts  

[LEGAL] All lists used for research and personal security purposes.  
Read provider TOS before commercial/automated use.
