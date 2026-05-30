# AirScope

A wireless recon automation tool that parses airodump-ng CSV output into actionable intelligence. Built for wireless penetration testers who want to skip the manual note-taking and get straight to attacking.

## What It Does

- Parses airodump-ng CSV files and displays a clean summary of all access points and clients
- Categorizes networks by encryption type (WPA3, WPA2, WPA, Open)
- Flags security weaknesses with prioritized alerts and attack recommendations
- Identifies probing clients for evil twin / Karma targeting
- Filters output by network type, client presence, or alerts only
- Exports results to text files for engagement documentation

## Installation

    git clone https://github.com/hexpluse/airscope.git
    cd airscope

No dependencies - uses only Python standard libraries.

## Usage

Basic scan summary:

    python airscope.py capture.csv

Alerts only with BSSIDs:

    python airscope.py capture.csv --alerts-only --show-bssid

Filter for transition mode networks with active clients:

    python airscope.py capture.csv --transition --has-clients

Export to file:

    python airscope.py capture.csv --alerts-only --output report.txt

## Flags

| Flag | Description |
|------|-------------|
| --alerts-only | Skip AP listing, show only security alerts |
| --show-bssid | Include BSSID in alert output |
| --has-clients | Only show APs with connected clients |
| --wpa2-only | Only show WPA2-PSK networks |
| --transition | Only show WPA3/WPA2 transition mode networks |
| --enterprise | Only show enterprise (MGT) networks |
| --output FILE | Export results to a text file |

## Example Output

    --------------------------------------------------
      Security Alerts
    --------------------------------------------------
      ch = Channel | cl = Connected Clients
      [!!] = Critical  [!] = Notable  [*] = Info  [?] = Investigate

      [!!] CoffeeShop_Free (ch:6) — OPEN → Evil twin / sniffing
      [!!] Linksys_Guest (ch:11) — OPEN → Evil twin / sniffing
      [!]  HomeNet-5G (ch:1), (cl:3) — Transition → Downgrade attack (verify MFP)
      [!]  CorpWiFi (ch:6), (cl:1) — Transition → Downgrade attack (verify MFP)
      [*]  Hidden (4A:2B:8C:1D:3E:F0) (ch:3), (cl:2) — Enterprise → Fake RADIUS

      --------------------------------------------------
        Probing Clients
      --------------------------------------------------
      [?]  A2:B4:C6:D8:E0:12 → Probing: Office_Net
      [?]  F1:E2:D3:C4:B5:A6 → Probing: HomeNet-5G

## Roadmap

- PCAP support with scapy for beacon frame RSN analysis
- Auto-extract MFP status and AKM suite from capture files
- Duplicate/related AP detection
- Channel-to-frequency mapping
- Interactive target selection with auto-generated attack commands
- PDF report generation

## Author

Built by hexpluse during CWPE (Certified Wireless Pentesting Expert) certification studies. Designed to automate the wireless reconnaissance workflow I found myself repeating nonstop during every assessment lol.

## License

MIT
