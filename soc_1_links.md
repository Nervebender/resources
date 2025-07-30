## 🕵️ Cyber Threat Intelligence Tools

These tools help analysts triage URLs, IPs, domains, and phishing campaigns:

* **UrlScan.io** – Submit and analyze URLs to see associated domains, IPs, technologies and screenshots. Useful for identifying malicious web indicators
  ‣ [UrlScan.io](https://urlscan.io/)

* **Abuse.ch** repositories – Track malware samples, botnets and blocklists (e.g. ThreatFox, SSL Blacklist, URLhaus).
  ‣ [Abuse.ch](https://abuse.ch/)

* **PhishTool** – A phishing analysis tool used to parse email headers, extract IOCs (IP, URLs), and triage inbound phishing emails.
  ‣ [PhishTool](https://phishtool.com/)

* **Cisco Talos Intelligence** – Threat intel platform providing data on domains and IPs, ASN, reputation and malware mapping.
  ‣ [TalosIntelligence.com](https://talosintelligence.com/)

---

## 🧾 YARA & OSINT Platforms
* **https://github.com/InQuest/awesome-yara** A curated list of awesome YARA rules, tools, and people.

* **https://github.com/Neo23x0/Loki** Loki - Simple IOC and YARA Scanner.

* **https://github.com/cuckoosandbox/cuckoo** Cuckoo Sandbox is an automated dynamic malware analysis system.

* **https://pypi.org/project/pefile/** pefile, Portable Executable reader module.

* **YARA** – Rule-based tool to identify malware samples or suspicious files based on patterns in hashes, strings, metadata. Used heavily in SOC L1 for file triage.

* **OpenCTI** and **MISP** – Threat intelligence platforms for collecting, structuring, and sharing Indicators of Compromise. OpenCTI organizes raw intel; MISP provides collaborative threat-sharing labs.

---

## 🌐 Network & Traffic Analysis Tools

These tools are central to detecting anomalies, investigating PCAPs, and writing Snort/IDS rules:

* **Wireshark** – GUI packet capture and analysis, essential for deep-dive PCAP inspection. Used across “Wireshark: The Basics”, “Packet Operations”, and Traffic Analysis tasks.
  ‣ [Wireshark.org](https://www.wireshark.org/)

* **TShark** – Command-line version of Wireshark, perfect for scripted packet queries, parsing PCAPs, hex dumps, filtering via CLI.
  ‣ [TShark documentation](https://www.wireshark.org/docs/man-pages/tshark.html)

* **Snort** – Signature‑based IDS/IPS for live network traffic detection and threat identification. Students write simple rules and observe alert logs.
  ‣ [Snort.org](https://snort.org/)

* **Zeek** – Formerly Bro, Zeek processes packet captures and network traffic into detailed logs (DNS, HTTP, connections) for automated analysis.
  ‣ [Zeek.org](https://zeek.org/)

* **Brim** (now known as ZUI) – GUI tool to explore Zeek and other log data, offering filtering and visual context for network events.
  ‣ [Brim Security](https://www.brimsecurity.com/)

* **NetworkMiner** – Passive network forensic analysis tool for extracting hosts, sessions, files, and metadata from PCAP captures.
  ‣ [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)

---

## 💻 Endpoint Security & System Monitoring Tools

Used for investigating alerts or suspicious behavior on host systems:

* **Sysinternals Suite (TCPView, Process Explorer, Autoruns)** – Monitor active processes, network connections, and persistent startup entries on Windows endpoints .
  ‣ [Microsoft Sysinternals](https://docs.microsoft.com/sysinternals/)

* **Sysmon** – Logs detailed system events (process creation, network activity, image loads) to aid detection via Windows Event logs and SIEM ingestion.
  ‣ [Sysmon guide](https://docs.microsoft.com/sysinternals/downloads/sysmon)

* **osquery** – SQL-like querying tool to inspect endpoint state (processes, packages, network, users) for threat hunting and situational awareness.
  ‣ [osquery.io](https://osquery.io/)

* **Wazuh** – Open-source EDR/Endpoint monitoring platform that collects logs (Sysmon, auth), applies alert rules, and integrates with SIEM tools for analysis.
  ‣ [Wazuh.com](https://wazuh.com/)

---

## 📊 SIEM & Forensics Tools (Preview / in later modules)

In later SOC Level 1 rooms and future extensions:

* **ELK Stack (Elasticsearch, Logstash, Kibana)** – For indexing and visualizing logs such as VPN and authentication events. Kibana allows custom visualizations using KQL filters.
  ‣ [Elastic.co](https://www.elastic.co/)

* **Splunk** – Splunk logs from multiple sources (IIS, Suricata, Sysmon) are trended through investigative timelines aligned with frameworks like the kill chain.
  ‣ [Splunk.com](https://www.splunk.com/)

* **Forensic tools** like **Autopsy**, **Redline**, **KAPE**, **Volatility**, and **Velociraptor** are mentioned in path extensions but more typical in SOC L2 or IR-focused rooms.

---

### ✅ Summary Table

| Module                     | Tools                                                               |
| -------------------------- | ------------------------------------------------------------------- |
| Threat Intelligence        | UrlScan.io, Abuse.ch, PhishTool, Cisco Talos, YARA, OpenCTI, MISP   |
| Network & Traffic Analysis | Wireshark, TShark, Snort, Zeek, Brim, NetworkMiner                  |
| Endpoint Monitoring & EDR  | Sysinternals, Sysmon, osquery, Wazuh                                |
| SIEM / Forensics (advance) | ELK Stack, Splunk, Autopsy, Volatility, KAPE, Redline, Velociraptor |
