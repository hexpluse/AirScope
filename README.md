AirScope
A wireless recon decision engine that parses airodump-ng captures into prioritized, actionable intelligence. Built for wireless penetration testers who want to skip the manual note-taking and get straight to attacking.
AirScope analyzes and decides. It does not attack. Once you know what to hit and how, you switch to the attack tool — hostapd, wacker, eaphammer, reaver, aireplay-ng, hashcat. AirScope's job is done at that point.
What It Does

Parses airodump-ng CSV files and displays a clean summary of all access points and clients
Enriches data with PCAP beacon frame analysis for MFP status and AKM suite details
Detects WPS-enabled networks from PCAP beacon frames for Pixie Dust / Reaver targeting
Detects PMKID presence from EAPOL frames — flags clientless offline crack viability
Identifies device manufacturers via IEEE OUI database lookup
Maps channels to frequencies for tools like wacker that require MHz values
Sorts networks by signal strength — closest targets first
Categorizes networks by encryption type (WPA3, WPA2, WPA, Open)
Flags security weaknesses with prioritized alerts and MFP-aware attack recommendations
Target lookup by SSID with automatic attack recommendation factoring MFP, WPS, and PMKID
Correlates hidden SSIDs with associated client probe data to infer likely network names
Passive captive portal detection from 802.11u IE, SSID patterns, and vendor fingerprinting
Identifies probing clients for evil twin / Karma targeting
Filters output by network type, client presence, PMKID capture, or alerts only
Exports results to text files for engagement documentation

Installation
git clone https://github.com/hexpluse/airscope.git
cd airscope
pip install scapy
Download the OUI database for vendor detection:
python -c "import urllib.request; urllib.request.urlretrieve('https://standards-oui.ieee.org/oui/oui.txt', 'oui.txt')"
Scapy and oui.txt are optional. CSV-only mode works without either — it just shows less information and tells you what's missing.
Usage
Basic scan summary:
python airscope.py capture.csv
Enrich with PCAP for MFP, WPS, AKM, and PMKID details:
python airscope.py capture.csv --pcap capture.cap
Alerts only — fastest workflow during an engagement:
python airscope.py capture.csv --pcap capture.cap --alerts-only
Target a specific network by name:
python airscope.py capture.csv --pcap capture.cap --target NETWORK-NAME
Show hidden SSID correlation — infer names from client probe data:
python airscope.py capture.csv --pcap capture.cap --hidden
Show all hidden APs including those with no client data:
python airscope.py capture.csv --pcap capture.cap --hidden-all
Filter for APs where a PMKID was captured — clientless crack targets:
python airscope.py capture.csv --pcap capture.cap --pmkid --alerts-only
Filter for transition mode networks with active clients:
python airscope.py capture.csv --transition --has-clients
Export to file:
python airscope.py capture.csv --alerts-only --output report.txt
Export target info for quick reference during attack setup:
python airscope.py capture.csv --pcap capture.cap --target NETWORK-NAME --output target.txt
Flags
FlagDescription--target SSIDShow detailed info and attack recommendation for a specific AP--alerts-onlySkip AP listing, show only security alerts--show-bssidInclude BSSID in alert output--show-clientsShow connected client MACs and vendors in alerts--has-clientsOnly show APs with connected clients--wpa2-onlyOnly show WPA2-PSK networks--transitionOnly show WPA3/WPA2 transition mode networks--enterpriseOnly show enterprise (MGT) networks--pcap FILEEnrich AP data with RSN/MFP/WPS/PMKID details from PCAP--output FILEExport results to a text file--hiddenShow hidden SSID correlation — only APs where a likely SSID was identified from associated client probes. Composes with --alerts-only and --target.--hidden-allLike --hidden but includes dead ends — hidden APs with no associated clients where no SSID can be inferred.--pmkidOnly show APs where a PMKID was captured. Requires --pcap. If none found, prints a clean message rather than an empty alert structure.
Example Output — Target Lookup
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
  PMKID:       Not found in capture
  Captive Portal: No signals detected
  Vendor:      Sagemcom Broadband SAS
  Attack:      SAE Downgrade (Transition Mode)

  ── CLIENTS (2) ────────────────────────────
  A1:B2:C3:D4:E5:F6 (Unknown vendor) → Probes: HomeNet-5G
  F6:E5:D4:C3:B2:A1 (Intel Corporate)
Example Output — Security Alerts
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
Example Output — Hidden SSID Correlation
  --------------------------------------------------
    Hidden SSID Correlation
  --------------------------------------------------

    [H]  Hidden AP — 02:CB:7A:0D:98:EF (Unknown vendor)
         ch:1 | 2412MHz | -70dBm | WPA2 MGT
         → Likely SSID(s): CorpNet  [from associated client probes]
         ├─ Client: 3E:EB:84:12:43:F2 (Unknown vendor)
            Probes: CorpNet
Captive Portal Detection
AirScope performs passive captive portal detection on open networks using three independent signals:

802.11u Interworking IE — AP is advertising network access policy (strongest signal, confidence: Likely)
SSID pattern matching — matches against known portal SSIDs from carriers, hospitality chains, and inflight wifi providers
Vendor fingerprinting — OUI patterns associated with portal deployments (Aruba, Meraki, Ruckus, Nomadix, etc.)

This is passive inference only. Confirmation requires active association. AirScope will always label portal findings with their confidence level and note that they are unconfirmed. A "Likely" finding means 802.11u was detected. A "Possible" finding means only SSID or vendor patterns matched.
PMKID Detection
AirScope parses EAPOL frames in the PCAP for PMKID presence. If captured, the attack recommendation in --target pivots to clientless offline cracking via hashcat — no deauth or associated client required.
Not found in capture does not mean the AP is not vulnerable — only that a PMKID was not present in this specific capture. Whether a PMKID is broadcast depends on the AP firmware.
Dependencies

Python 3.x (standard library only for CSV mode)
scapy (optional, for PCAP enrichment): pip install scapy
oui.txt (optional, for vendor identification): download from IEEE

Version History

v4.4.1 — --pmkid filter flag to show only APs with captured PMKIDs
v4.4 — PMKID detection from EAPOL frames in PCAP
v4.3 — MFP-aware attack recommendations in --target
v4.2 — Passive captive portal detection (802.11u, SSID patterns, vendor fingerprinting)
v4.1 — Hidden SSID correlation with --hidden and --hidden-all flags
v4.0 — Target lookup with --target flag and attack recommendations
v3.5 — Code cleanup
v3.4 — Signal strength sorting, visual redesign, --show-clients flag
v3.3 — WPS detection from PCAP beacon frames
v3.2 — Channel-to-frequency mapping
v3.1 — OUI vendor lookup for manufacturer identification
v3.0 — PCAP support with scapy for RSN/MFP enrichment
v2.5 — Export to file with --output
v2.3 — Argparse filters
v2.2 — Security alerts with attack recommendations
v1.0 — CSV parsing and AP/client display

Author
Built by hexpluse during CWPE (Certified Wireless Pentesting Expert) certification studies. Designed to automate the wireless reconnaissance workflow I found myself repeating manually during every assessment.
License
MIT
