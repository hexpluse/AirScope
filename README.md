# AirScope

A wireless recon automation tool that parses airodump-ng CSV output into actionable intelligence. Built for wireless penetration testers who want to skip the manual note-taking and get straight to attacking.

## What It Does

- Parses airodump-ng CSV files and displays a clean summary of all access points and clients
- Enriches data with PCAP beacon frame analysis for MFP status and AKM suite details
- Detects WPS-enabled networks from PCAP beacon frames for Pixie Dust / Reaver targeting
- Identifies device manufacturers via IEEE OUI database lookup
- Maps channels to frequencies for tools like wacker that require MHz values
- Sorts networks by signal strength — closest targets first
- Categorizes networks by encryption type (WPA3, WPA2, WPA, Open)
- Flags security weaknesses with prioritized alerts and attack recommendations
- Target lookup by SSID with automatic attack recommendation
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

Enrich with PCAP for MFP, WPS, and AKM details:

    python airscope.py capture.csv --pcap capture.cap

Target a specific network by name:

    python airscope.py capture.csv --pcap capture.cap --target NETWORK-NAME

Alerts only with BSSIDs and client details:

    python airscope.py capture.csv --alerts-only --show-bssid --show-clients

Filter for transition mode networks with active clients:

    python airscope.py capture.csv --transition --has-clients

Export to file:

    python airscope.py capture.csv --alerts-only --output report.txt

Export target info for quick reference during attack setup:

    python airscope.py capture.csv --pcap capture.cap --target NETWORK-NAME --output target.txt

## Flags

| Flag | Description |
|------|-------------|
| --target SSID | Show detailed info and attack recommendation for a specific AP |
| --alerts-only | Skip AP listing, show only security alerts |
| --show-bssid | Include BSSID in alert output |
| --show-clients | Show connected client MACs and vendors in alerts |
| --has-clients | Only show APs with connected clients |
| --wpa2-only | Only show WPA2-PSK networks |
| --transition | Only show WPA3/WPA2 transition mode networks |
| --enterprise | Only show enterprise (MGT) networks |
| --pcap FILE | Enrich AP data with RSN/MFP/WPS details from PCAP |
| --output FILE | Export results to a text file |

## Example Output — Target Lookup

    ── TARGET INFO ─────────────────────────────
    SSID:        HomeNet-5G
    BSSID:       A4:B1:C2:D3:E4:F5
    Channel:     4
    Frequency:   2427 MHz
    Signal:      -46 dBm
    Encryption:  WPA3 WPA2 CCMP
    Auth:        SAE PSK
    MFP:         Capable (not required)
    WPS:         Enabled
    Vendor:      Sagemcom Broadband SAS
    Attack:      SAE Downgrade (Transition Mode)

    ── CLIENTS (2) ────────────────────────────
    A1:B2:C3:D4:E5:F6 (Unknown vendor) → Probes: HomeNet-5G
    F6:E5:D4:C3:B2:A1 (Intel Corporate)

## Example Output — Security Alerts

    --------------------------------------------------
      Security Alerts
    --------------------------------------------------
      [!!] = Critical  [!] = Notable  [*] = Info
      MFP: Required = Deauth blocked
      MFP: Capable/Disabled = Deauth viable

      ── CRITICAL ────────────────────────────────

      [!!] CoffeeShop_Free
           ch:6 | 2437MHz | -52dBm | 0 client(s)
           → OPEN → Evil twin / sniffing
           └─ Vendor: TP-LINK TECHNOLOGIES CO.,LTD.

      ── NOTABLE ─────────────────────────────────

      [!]  HomeNet-5G
           ch:4 | 2427MHz | -46dBm | 2 client(s)
           → Transition → Downgrade | MFP: Capable (not required)
           → WPS ENABLED → Pixie Dust / Reaver
           └─ Vendor: Sagemcom Broadband SAS

      [!]  Fios-Home
           ch:1 | 2412MHz | -69dBm | 0 client(s)
           → WPA2-PSK + WPS ENABLED → Pixie Dust / Reaver
           └─ Vendor: Arcadyan Corporation

      ── INFORMATIONAL ───────────────────────────

      [*]  Hidden (4A:2B:8C:1D:3E:F0)
           ch:3 | 2422MHz | -70dBm | 1 client(s)
           → Enterprise → Fake RADIUS

      ── INVESTIGATE ─────────────────────────────

      [?]  A2:B4:C6:D8:E0:12 (Espressif Inc.)
           → Probing: Office_Net

## Dependencies

- Python 3.x (standard library only for CSV mode)
- scapy (optional, for PCAP enrichment with MFP and WPS): pip install scapy
- oui.txt (optional, for vendor identification): download from IEEE

## Version History

- v4.0 — Target lookup with --target flag and attack recommendations
- v3.5 — Code cleanup
- v3.4 — Signal strength sorting, visual redesign, --show-clients flag
- v3.3 — WPS detection from PCAP beacon frames
- v3.2 — Channel-to-frequency mapping
- v3.1 — OUI vendor lookup for manufacturer identification
- v3.0 — PCAP support with scapy for RSN/MFP enrichment
- v2.5 — Export to file with --output
- v2.3 — Argparse filters
- v2.2 — Security alerts with attack recommendations
- v1.0 — CSV parsing and AP/client display

## Author

Built by hexpluse during CWPE (Certified Wireless Pentesting Expert) certification studies. Designed to automate the wireless reconnaissance workflow I found myself repeating manually during every assessment.

## License

MIT
