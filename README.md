# AirScope

A wireless recon automation tool that parses airodump-ng CSV output into actionable intelligence. Built for wireless penetration testers who want to skip the manual note-taking and get straight to attacking.

## What It Does

- Parses airodump-ng CSV files and displays a clean summary of all access points and clients
- Enriches data with PCAP beacon frame analysis for MFP status and AKM suite details
- Identifies device manufacturers via IEEE OUI database lookup
- Categorizes networks by encryption type (WPA3, WPA2, WPA, Open)
- Flags security weaknesses with prioritized alerts and attack recommendations
- Identifies probing clients for evil twin / Karma targeting
- Filters output by network type, client presence, or alerts only
- Exports results to text files for engagement documentation

## Installation

    git clone https://github.com/hexpluse/airscope.git
    cd airscope
    pip install scapy

Download the OUI database for vendor detection:

    python -c "import urllib.request; urllib.request.urlretrieve('https://standards-oui.ieee.org/oui/oui.txt', 'oui.txt')"

## Usage

Basic scan summary:

    python airscope.py capture.csv

Enrich with PCAP for MFP and AKM details:

    python airscope.py capture.csv --pcap capture.cap

Alerts only with BSSIDs:

    python airscope.py capture.csv --alerts-only --show-bssid

Filter for transition mode networks with active clients:

    python airscope.py capture.csv --transition --has-clients

Export to file:

    python airscope.py capture.csv --alerts-only --output report.txt

Full recon (CSV + PCAP + alerts + export):

    python airscope.py capture.csv --pcap capture.cap --alerts-only --show-bssid --output findings.txt

## Flags

| Flag | Description |
|------|-------------|
| --alerts-only | Skip AP listing, show only security alerts |
| --show-bssid | Include BSSID in alert output |
| --has-clients | Only show APs with connected clients |
| --wpa2-only | Only show WPA2-PSK networks |
| --transition | Only show WPA3/WPA2 transition mode networks |
| --enterprise | Only show enterprise (MGT) networks |
| --pcap FILE | Enrich AP data with RSN/MFP details from PCAP |
| --output FILE | Export results to a text file |

## Example Output

    --------------------------------------------------
      Security Alerts
    --------------------------------------------------
      ch = Channel | cl = Connected Clients
      [!!] = Critical  [!] = Notable  [*] = Info  [?] = Investigate
      MFP: Required = Deauth blocked | Capable/Disabled = Deauth viable

      [!!] CoffeeShop_Free (ch:6) — OPEN → Evil twin / sniffing
           └─ Vendor: TP-LINK TECHNOLOGIES CO.,LTD.
      [!!] Linksys_Guest (ch:11) — OPEN → Evil twin / sniffing
           └─ Vendor: Belkin International Inc.
      [!]  HomeNet-5G (ch:1), (cl:3) — Transition → Downgrade | MFP: Capable (not required)
           └─ Vendor: ASUSTek COMPUTER INC.
      [!]  CorpWiFi (ch:6), (cl:1) — SAE Solo → Wacker / Evil twin | MFP: Required
           └─ Vendor: Cisco Systems, Inc.
      [*]  Hidden (4A:2B:8C:1D:3E:F0) (ch:3), (cl:2) — Enterprise → Fake RADIUS

      --------------------------------------------------
        Probing Clients
      --------------------------------------------------
      [?]  A2:B4:C6:D8:E0:12 (Espressif Inc.) → Probing: Office_Net
      [?]  F1:E2:D3:C4:B5:A6 (Intel Corporate) → Probing: HomeNet-5G

## Dependencies

- Python 3.x (standard library only for CSV mode)
- scapy (optional, for PCAP enrichment): pip install scapy
- oui.txt (optional, for vendor identification): download from IEEE

## Roadmap

- [ ] Channel-to-frequency mapping
- [ ] Duplicate/related AP detection
- [ ] Interactive target selection with auto-generated attack commands
- [ ] Compare scans (diff two captures)
- [ ] PDF report generation

## Author

Built by hexpluse during CWPE (Certified Wireless Pentesting Expert) certification studies. Designed to automate the wireless reconnaissance workflow I found myself repeating manually during every assessment.

## License

MIT
