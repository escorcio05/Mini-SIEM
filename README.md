# 🕵️‍♂️ Mini-SIEM: SSH Log Parser & Threat Intelligence

A lightweight Python-based Security Information and Event Management (SIEM) tool. This script acts as a log parser that analyzes SSH authentication logs to detect brute-force attacks and enriches the attacker's IP data with geographical tracking.

## 🎯 Project Objective
This project was built to demonstrate core **Security Operations Center (SOC)** capabilities:
* **Log Parsing & RegEx:** Extracting critical Indicators of Compromise (IoCs) from raw system logs using Regular Expressions.
* **Threat Intelligence / Data Enrichment:** Integrating external REST APIs to map malicious IP addresses to their country of origin.
* **Automated Alerting:** Identifying repeated failed authentication attempts (Brute-Force) and generating actionable security alerts.

## 🚀 Features
* Analyzes standard Linux `auth.log` files.
* Uses Regex to accurately capture IPv4 addresses of attackers.
* Integrates with `ip-api.com` to provide GeoIP location of the threats.
* Threshold-based alerting (e.g., triggers a RED ALERT after 3 failed attempts).

## 🛠️ How to Run

1. Clone the repository:
   ```bash
   git clone [https://github.com/TEU-USER/Mini-SIEM.git](https://github.com/TEU-USER/Mini-SIEM.git)
   cd Mini-SIEM
   
## 👥 Authors
Guilherme Escórcio - [escorcio05](https://github.com/escorcio05)<br>
Leonardo Silva - [leonelas03](https://github.com/leonelas03)
