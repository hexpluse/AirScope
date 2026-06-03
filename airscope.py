import sys
import argparse
from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt, EAPOL
VERSION = "4.5.3"

try:
	from colorama import init, Fore, Style
	init(autoreset=True)
	C_RED     = Fore.RED
	C_YELLOW  = Fore.YELLOW
	C_BLUE    = Fore.BLUE
	C_MAGENTA = Fore.MAGENTA
	C_CYAN    = Fore.CYAN
	C_ORANGE  = Fore.YELLOW
	C_GREEN   = Fore.GREEN
	C_DIM     = Style.DIM
	C_BOLD    = Style.BRIGHT
	C_RESET   = Style.RESET_ALL
except ImportError:
	C_RED = C_YELLOW = C_BLUE = C_MAGENTA = C_CYAN = C_ORANGE = C_GREEN = C_DIM = C_BOLD = C_RESET = ""
	print("  Note: install colorama for color output (pip install colorama)")

def load_oui(filepath="oui.txt"):
	"""Load OUI database into a lookup dictionary"""
	oui_db = {}
	try:
		with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
			for line in f:
				if "(hex)" in line:
					parts = line.split("(hex)")
					prefix = parts[0].strip().replace("-", ":").upper()
					vendor = parts[1].strip()
					oui_db[prefix] = vendor
	except FileNotFoundError:
		print("  Warning: oui.txt not found — run with OUI database for vendor detection")
	return oui_db

def lookup_vendor(mac, oui_db):
	"""Look up vendor from MAC address using OUI database"""
	prefix = mac.upper()[:8]
	return oui_db.get(prefix, "Unknown vendor")

CHANNEL_FREQ = {
	"1": 2412, "2": 2417, "3": 2422, "4": 2427,
	"5": 2432, "6": 2437, "7": 2442, "8": 2447,
	"9": 2452, "10": 2457, "11": 2462, "12": 2467,
	"13": 2472, "14": 2484,
	"36": 5180, "40": 5200, "44": 5220, "48": 5240,
	"52": 5260, "56": 5280, "60": 5300, "64": 5320,
	"100": 5500, "104": 5520, "108": 5540, "112": 5560,
	"116": 5580, "120": 5600, "124": 5620, "128": 5640,
	"132": 5660, "136": 5680, "140": 5700, "144": 5720,
	"149": 5745, "153": 5765, "157": 5785, "161": 5805, "165": 5825
}

# Known captive portal SSID patterns — partial matches, case-insensitive
CAPTIVE_PORTAL_SSIDS = [
	"xfinitywifi", "xfinity", "boingo", "attwifi", "att wifi",
	"twc wifi", "cablewifi", "_guest", "-guest", "guest_",
	"passpoint", "hotspot", "_nomap", "hotel", "marriott",
	"hilton", "hyatt", "airportnet", "airport wifi", "transit wifi",
	"starbucks", "google starbucks", "united wifi", "delta wifi",
	"southwest wifi", "aa inflight", "gogoinflight", "gogo inflight",
]

# Vendor OUI prefixes commonly associated with captive portal deployments
# (hospitality controllers, carrier hotspot gear)
CAPTIVE_PORTAL_VENDORS = [
	"ruckus", "aruba", "cisco meraki", "meraki", "nomadix",
	"aptilo", "cloud4wi", "purple wifi", "aislelabs",
]

def parse_airodump(filepath):
	"""Parse airodump-ng CSV into APs and clients"""
	aps = []
	clients = []
	section = None

	with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
		for line in f:
			line = line.strip()

			if line.startswith("BSSID, First time seen"):
				section = "ap"
				continue
			elif line.startswith("Station MAC"):
				section = "client"
				continue

			if not line:
				continue

			row = [col.strip() for col in line.split(",")]

			if section == "ap" and len(row) >= 14:
				bssid = row[0]
				if not bssid or bssid == "BSSID" or bssid == "00:00:00:00:00:00":
					continue
				ap = {
					"bssid": bssid,
					"channel": row[3],
					"encryption": row[5],
					"cipher": row[6],
					"auth": row[7],
					"power": row[8] if len(row) > 8 else "0",
					"essid": row[13],
				}
				aps.append(ap)

			elif section == "client" and len(row) >= 7:
				mac = row[0]
				if not mac or mac == "Station MAC":
					continue
				client = {
					"mac": mac,
					"bssid": row[5],
					"probes": row[6] if len(row) > 6 else "",
				}
				clients.append(client)

	return aps, clients

def enrich_from_pcap(filepath, aps):
	"""Parse PCAP beacon frames to extract RSN info, MFP status, and WPS"""
	packets = rdpcap(filepath)
	for pkt in packets:
		if not pkt.haslayer(Dot11Beacon):
			continue
		bssid = pkt[Dot11].addr2.upper()
		matching_ap = None
		for ap in aps:
			if ap["bssid"].upper() == bssid:
				matching_ap = ap
				break
		if not matching_ap:
			continue
		elt = pkt[Dot11Beacon].payload
		while isinstance(elt, Dot11Elt):
			if elt.ID == 221 and len(elt.info) >= 4:
				if elt.info[:4] == b'\x00\x50\xf2\x04':
					matching_ap["wps"] = True
			# 802.11u Interworking IE — AP is advertising network access policy
			# Strongest passive signal for captive portal presence
			if elt.ID == 107:
				matching_ap["interworking"] = True
			if elt.ID == 48 and len(elt.info) >= 8 and "mfp" not in matching_ap:
				rsn_bytes = elt.info
				try:
					offset = 2
					offset += 4
					pairwise_count = int.from_bytes(rsn_bytes[offset:offset+2], 'little')
					offset += 2 + (pairwise_count * 4)
					akm_count = int.from_bytes(rsn_bytes[offset:offset+2], 'little')
					offset += 2
					akm_types = []
					for i in range(akm_count):
						akm_suite = rsn_bytes[offset:offset+4]
						akm_type_byte = akm_suite[3]
						if akm_type_byte == 1:
							akm_types.append("802.1X")
						elif akm_type_byte == 2:
							akm_types.append("PSK")
						elif akm_type_byte == 6:
							akm_types.append("802.1X-SHA256")
						elif akm_type_byte == 8:
							akm_types.append("SAE")
						elif akm_type_byte == 18:
							akm_types.append("OWE")
						else:
							akm_types.append(f"Unknown({akm_type_byte})")
						offset += 4
					matching_ap["akm_details"] = " + ".join(akm_types)
					if offset + 2 <= len(rsn_bytes):
						rsn_caps = int.from_bytes(rsn_bytes[offset:offset+2], 'little')
						mfp_capable = bool(rsn_caps & 0x80)
						mfp_required = bool(rsn_caps & 0x40)
						if mfp_required:
							matching_ap["mfp"] = "Required"
						elif mfp_capable:
							matching_ap["mfp"] = "Capable (not required)"
						else:
							matching_ap["mfp"] = "Disabled"
				except (IndexError, ValueError):
					pass
			elt = elt.payload if hasattr(elt, 'payload') and isinstance(elt.payload, Dot11Elt) else None

	# Second pass — EAPOL frames for PMKID detection
	# PMKID is in EAPOL message 1 of the 4-way handshake, key data field
	# Format: RSN IE header (00:0f:ac:04) followed by 16-byte PMKID
	for pkt in packets:
		if not pkt.haslayer(EAPOL):
			continue
		try:
			# AP is the source in message 1 (addr2 = transmitter)
			ap_mac = pkt[Dot11].addr2.upper()
			matching_ap = None
			for ap in aps:
				if ap["bssid"].upper() == ap_mac:
					matching_ap = ap
					break
			if not matching_ap:
				continue
			if matching_ap.get("pmkid"):
				continue
			eapol_raw = bytes(pkt[EAPOL])
			pmkid_marker = b'\x00\x0f\xac\x04'
			marker_pos = eapol_raw.find(pmkid_marker)
			if marker_pos != -1 and len(eapol_raw) >= marker_pos + 4 + 16:
				matching_ap["pmkid"] = True
		except Exception:
			pass

	return aps

def correlate_hidden_ssids(aps, clients):
	"""
	Correlate hidden APs with client probe data to infer likely SSIDs.

	Two correlation methods:
	  1. Associated client: a client's BSSID matches a hidden AP — their probes
	     likely name that network (high confidence).
	  2. Orphan probe: a probing client's probe SSIDs don't match any visible AP —
	     flagged as a possible hidden network probe (investigative).

	Returns a list of finding dicts for display_hidden_correlation().
	"""
	hidden_aps = [ap for ap in aps if not ap["essid"]]
	if not hidden_aps:
		return []

	findings = []

	for ap in hidden_aps:
		ap_bssid = ap["bssid"].upper()
		associated_clients = [c for c in clients if c["bssid"].upper() == ap_bssid]

		# Method 1: clients associated directly to the hidden AP
		if associated_clients:
			candidate_ssids = []
			for c in associated_clients:
				probes = [p.strip() for p in c["probes"].split(",") if p.strip()]
				for probe in probes:
					if probe not in candidate_ssids:
						candidate_ssids.append(probe)

			findings.append({
				"type": "associated",
				"bssid": ap["bssid"],
				"channel": ap["channel"],
				"power": ap["power"],
				"encryption": ap["encryption"],
				"auth": ap["auth"],
				"clients": associated_clients,
				"candidate_ssids": candidate_ssids,
			})
		else:
			# Hidden AP with no associated clients — record it for display
			findings.append({
				"type": "no_clients",
				"bssid": ap["bssid"],
				"channel": ap["channel"],
				"power": ap["power"],
				"encryption": ap["encryption"],
				"auth": ap["auth"],
				"clients": [],
				"candidate_ssids": [],
			})

	return findings

def display_hidden_correlation(findings, oui_db, show_all=False):
	"""Display hidden SSID correlation results"""
	if not findings:
		return

	print("-" * 50)
	print("  Hidden SSID Correlation")
	print("-" * 50)
	print()

	for f in findings:
		if f["type"] == "associated":
			vendor = lookup_vendor(f["bssid"], oui_db)
			freq = CHANNEL_FREQ.get(f["channel"], "?")
			print(f"  {C_CYAN}[H]  Hidden AP — {f['bssid']}{C_RESET} ({vendor})")
			print(f"       ch:{f['channel']} | {freq}MHz | {f['power']}dBm | {f['encryption']} {f['auth']}")

			if f["candidate_ssids"]:
				ssid_list = ", ".join(f["candidate_ssids"])
				print(f"       {C_CYAN}→ Likely SSID(s): {ssid_list}{C_RESET}  [from associated client probes]")
			else:
				print(f"       → No probe data from associated clients")

			for c in f["clients"]:
				cv = lookup_vendor(c["mac"], oui_db)
				print(f"       ├─ Client: {c['mac']} ({cv})")
				if c.get("probes"):
					print(f"          Probes: {c['probes']}")
			print()

		elif f["type"] == "no_clients" and show_all:
			vendor = lookup_vendor(f["bssid"], oui_db)
			freq = CHANNEL_FREQ.get(f["channel"], "?")
			print(f"  [H]  Hidden AP — {f['bssid']} ({vendor})")
			print(f"       ch:{f['channel']} | {freq}MHz | {f['power']}dBm | {f['encryption']} {f['auth']}")
			print(f"       → No associated clients — SSID cannot be inferred from this data")
			print()


def captive_portal_signals(ap, oui_db):
	"""
	Assess passive signals that suggest a captive portal.
	Returns (confidence, reasons) where confidence is
	"Likely", "Possible", or None.

	IMPORTANT: This is passive inference only. Confirmation
	requires association. Never treat this as a confirmed finding.
	"""
	reasons = []

	# Signal 1 — 802.11u Interworking IE present (strongest passive indicator)
	if ap.get("interworking"):
		reasons.append("802.11u Interworking IE detected")

	# Signal 2 — SSID matches known captive portal patterns
	essid = ap.get("essid", "").lower()
	for pattern in CAPTIVE_PORTAL_SSIDS:
		if pattern in essid:
			reasons.append(f"SSID matches known portal pattern ({pattern})")
			break

	# Signal 3 — Vendor is known captive portal hardware/controller
	vendor = lookup_vendor(ap["bssid"], oui_db).lower()
	for v in CAPTIVE_PORTAL_VENDORS:
		if v in vendor:
			reasons.append(f"Vendor associated with portal deployments ({vendor})")
			break

	if not reasons:
		return None, []

	# 802.11u alone or with corroboration = Likely
	# Pattern/vendor match only = Possible
	if ap.get("interworking"):
		confidence = "Likely"
	else:
		confidence = "Possible"

	return confidence, reasons

def display_results(aps, clients, oui_db):
	"""Print a clean recon summary"""
	print("=" * 50)
	print("  AirScope — Wireless Recon Summary")
	print("=" * 50)
	print()

	for i, ap in enumerate(aps, 1):
		ap_clients = [c for c in clients if c["bssid"] == ap["bssid"]]

		print(f"[{i}] {ap['essid']}")
		vendor = lookup_vendor(ap['bssid'], oui_db)
		print(f"    BSSID:    {ap['bssid']} ({vendor})")
		freq = CHANNEL_FREQ.get(ap['channel'], "?")
		print(f"    Channel:  {ap['channel']} ({freq} MHz)")
		print(f"    Signal:   {ap['power']} dBm")
		print(f"    Encrypt:  {ap['encryption']} {ap['cipher']} {ap['auth']}")
		print(f"    Clients:  {len(ap_clients)}")

		for c in ap_clients:
			print(f"              └─ {c['mac']} ({lookup_vendor(c['mac'], oui_db)})")
			if c["probes"]:
				print(f"                 Probes: {c['probes']}")

		print()

def display_stats(aps, clients):
	"""Print Summary Statistics"""

	wpa3_count = 0
	wpa2_count = 0
	wpa_count = 0
	opn_count = 0
	hidden_count = 0

	for ap in aps:
		if "WPA3" in ap["encryption"]:
			wpa3_count += 1
		elif "WPA2" in ap["encryption"]:
			wpa2_count += 1
		elif "WPA" in ap["encryption"]:
			wpa_count += 1
		elif "OPN" in ap["encryption"]:
			opn_count += 1

		if not ap["essid"]:
			hidden_count += 1

	associated = 0
	probing = 0

	for client in clients:
		if "(not associated)" in client["bssid"]:
			probing += 1
		else:
			associated += 1

	print("-" * 50)
	print("  Summary")
	print("-" * 50)
	print(f"  Total APs:      {len(aps)}")
	print(f"    WPA3:          {wpa3_count}")
	print(f"    WPA2:          {wpa2_count}")
	print(f"    WPA:           {wpa_count}")
	print(f"    Open:          {opn_count}")
	print(f"    Hidden SSID:   {hidden_count}")
	print(f"  Total Clients:   {len(clients)}")
	print(f"    Associated:    {associated}")
	print(f"    Probing:       {probing}")

def display_target(aps, clients, target, oui_db):
	"""Display detailed info for a specific AP target"""
	ap = None
	for a in aps:
		if a["essid"].upper() == target.upper():
			ap = a
			break

	if not ap:
		print(f"  Error: Target '{target}' not found.")
		return

	vendor = lookup_vendor(ap["bssid"], oui_db)
	freq = CHANNEL_FREQ.get(ap["channel"], "?")
	mfp = ap.get("mfp", "Unknown — verify in Wireshark")
	wps = "Enabled" if ap.get("wps") else "Not detected"
	ap_clients = [c for c in clients if c["bssid"] == ap["bssid"]]

	auth = ap["auth"]
	enc = ap["encryption"]
	mfp_status = ap.get("mfp", "Unknown")
	mfp_required = mfp_status == "Required"
	mfp_unknown = mfp_status == "Unknown"

	attack_note = ""

	if "OPN" in enc:
		attack = "Evil Twin / Sniffing (Open Network)"
	elif "SAE" in auth and "PSK" in auth:
		attack = "SAE Downgrade (Transition Mode)"
		if mfp_required:
			attack_note = "MFP Required — deauth blocked; evil twin or passive capture only"
		elif mfp_unknown:
			attack_note = "MFP status unknown — verify in Wireshark before attempting deauth"
	elif "SAE" in auth:
		attack = "Online Brute-Force (Wacker) or SAE Collider Evil Twin"
		if mfp_required:
			attack_note = "MFP Required — deauth blocked; evil twin approach recommended"
		elif mfp_unknown:
			attack_note = "MFP status unknown — verify in Wireshark before attempting deauth"
	elif "MGT" in auth:
		attack = "Evil Twin + Fake RADIUS (Enterprise)"
	elif "WPA2" in enc and ap.get("wps"):
		attack = "WPS Attack (Pixie Dust / Reaver)"
	elif "WPA2" in enc:
		if ap.get("pmkid") and mfp_required:
			attack = "PMKID Crack (clientless) — hashcat -m 22000"
			attack_note = "MFP Required (deauth blocked) but PMKID captured — offline crack viable without deauth"
		elif ap.get("pmkid"):
			attack = "PMKID Crack (clientless) — hashcat -m 22000"
			attack_note = "No deauth or client required — PMKID captured from AP directly"
		elif mfp_required:
			attack = "Evil Twin (MFP Required — deauth blocked, handshake capture not viable)"
			attack_note = "Switch to evil twin — deauth will not force client reconnect"
		elif mfp_unknown:
			attack = "Deauth + Capture Handshake + Hashcat"
			attack_note = "MFP status unknown — verify in Wireshark; deauth may be blocked"
		else:
			attack = "Deauth + Capture Handshake + Hashcat"
	else:
		attack = "Manual analysis needed"

	print()
	print(f"  ── TARGET INFO ─────────────────────────────")
	print(f"  SSID:        {ap['essid'] if ap['essid'] else 'Hidden'}")
	print(f"  BSSID:       {ap['bssid']}")
	print(f"  Channel:     {ap['channel']}")
	print(f"  Frequency:   {freq} MHz")
	print(f"  Signal:      {ap['power']} dBm")
	print(f"  Encryption:  {enc} {ap['cipher']}")
	print(f"  Auth:        {auth}")
	print(f"  MFP:         {mfp}")
	print(f"  WPS:         {wps}")
	pmkid_status = "Captured — clientless crack viable (hashcat -m 22000)" if ap.get("pmkid") else "Not found in capture"
	print(f"  PMKID:       {pmkid_status}")
	portal_confidence, portal_reasons = captive_portal_signals(ap, oui_db)
	if portal_confidence:
		print(f"  Captive Portal: {portal_confidence} (passive only — unconfirmed)")
		for r in portal_reasons:
			print(f"               → {r}")
	else:
		print(f"  Captive Portal: No signals detected")
	print(f"  Vendor:      {vendor}")
	print(f"  Attack:      {C_RED}{attack}{C_RESET}")
	if attack_note:
		print(f"  Note:        {C_YELLOW}{attack_note}{C_RESET}")
	print()

	if ap_clients:
		print(f"  ── CLIENTS ({len(ap_clients)}) ────────────────────────────")
		for c in ap_clients:
			cv = lookup_vendor(c['mac'], oui_db)
			probe_info = f" → Probes: {c['probes']}" if c.get("probes") else ""
			print(f"  {c['mac']} ({cv}){probe_info}")
		print()

def display_alerts(aps, clients, show_bssid=False, oui_db={}, show_clients=False):
	"""Flag security weaknesses, sorted by priority"""

	alerts = []

	for ap in aps:
		bssid_info = f" [{ap['bssid']}]" if show_bssid else ""
		if ap["essid"]:
			name = ap["essid"]
		else:
			name = "Hidden (" + ap["bssid"] + ")"
			bssid_info = ""
		enc = ap["encryption"]
		auth = ap["auth"]
		ch = ap["channel"]
		freq = CHANNEL_FREQ.get(ch, "?")
		pwr = ap.get("power", "?")
		ap_clients = [c for c in clients if c["bssid"] == ap["bssid"]]
		cl = len(ap_clients)
		mfp = ap.get("mfp", "Unknown — verify in Wireshark")
		vendor = lookup_vendor(ap["bssid"], oui_db)
		vendor_line = f"\n       └─ Vendor: {vendor}" if vendor != "Unknown vendor" else ""
		wps_line = f"\n       {C_YELLOW}→ WPS ENABLED → Pixie Dust / Reaver{C_RESET}" if ap.get("wps") else ""
		client_lines = ""
		if show_clients and ap_clients:
			for c in ap_clients:
				cv = lookup_vendor(c['mac'], oui_db)
				client_lines += f"\n       ├─ Client: {c['mac']} ({cv})"
				if c.get("probes"):
					client_lines += f" → Probes: {c['probes']}"

		meta = f"       ch:{ch} | {freq}MHz | {pwr}dBm | {cl} client(s)"

		if "OPN" in enc:
			portal_confidence, portal_reasons = captive_portal_signals(ap, oui_db)
			if portal_confidence:
				reason_str = "; ".join(portal_reasons)
				portal_line = f"\n       → Captive Portal: {portal_confidence} (passive only — unconfirmed)\n         Signals: {reason_str}\n       → Consider: portal cloning / credential harvesting"
			else:
				portal_line = ""
			alert_text = f"  {C_RED}[!!] {name}{bssid_info}{C_RESET}\n{meta}\n       {C_RED}→ OPEN → Evil twin / sniffing{C_RESET}{portal_line}{vendor_line}{client_lines}"
			alerts.append((1, alert_text))
		elif "WPA" in enc and "WPA2" not in enc:
			alert_text = f"  {C_RED}[!!] {name}{bssid_info}{C_RESET}\n{meta}\n       {C_RED}→ Legacy WPA → Capture + crack{C_RESET}{wps_line}{vendor_line}{client_lines}"
			alerts.append((1, alert_text))
		elif "SAE" in auth and "PSK" in auth:
			alert_text = f"  {C_YELLOW}[!]  {name}{bssid_info}{C_RESET}\n{meta}\n       {C_YELLOW}→ Transition → Downgrade | MFP: {mfp}{C_RESET}{wps_line}{vendor_line}{client_lines}"
			alerts.append((2, alert_text))
		elif "SAE" in auth:
			alert_text = f"  {C_YELLOW}[!]  {name}{bssid_info}{C_RESET}\n{meta}\n       {C_YELLOW}→ SAE Solo → Wacker / Evil twin | MFP: {mfp}{C_RESET}{vendor_line}{client_lines}"
			alerts.append((2, alert_text))
		elif "MGT" in auth:
			alert_text = f"  {C_BLUE}[*]  {name}{bssid_info}{C_RESET}\n{meta}\n       {C_BLUE}→ Enterprise → Fake RADIUS{C_RESET}{vendor_line}{client_lines}"
			alerts.append((3, alert_text))
		elif "WPA2" in enc and "PSK" in auth and ap.get("wps"):
			alert_text = f"  {C_YELLOW}[!]  {name}{bssid_info}{C_RESET}\n{meta}\n       {C_YELLOW}→ WPA2-PSK + WPS ENABLED → Pixie Dust / Reaver{C_RESET}{vendor_line}{client_lines}"
			alerts.append((2, alert_text))
		elif "WPA2" in enc and "PSK" in auth and ap.get("pmkid"):
			alert_text = f"  {C_YELLOW}[!]  {name}{bssid_info}{C_RESET}\n{meta}\n       {C_YELLOW}→ WPA2-PSK + PMKID captured → Clientless crack (hashcat -m 22000){C_RESET}{vendor_line}{client_lines}"
			alerts.append((2, alert_text))
		elif "WPA2" in enc and "PSK" in auth:
			mfp_required = mfp == "Required"
			mfp_unknown = "Unknown" in mfp
			if mfp_required:
				mfp_line = f"\n       {C_RED}→ MFP Required — deauth blocked | Consider: evil twin{C_RESET}"
			elif mfp_unknown:
				mfp_line = f"\n       {C_YELLOW}→ MFP Unknown — verify in Wireshark before attempting deauth{C_RESET}"
			else:
				mfp_line = f"\n       {C_YELLOW}→ Deauth + capture handshake | MFP: {mfp}{C_RESET}"
			alert_text = f"  {C_YELLOW}[!]  {name}{bssid_info}{C_RESET}\n{meta}{mfp_line}{vendor_line}{client_lines}"
			alerts.append((2, alert_text))

	alerts.sort(key=lambda x: x[0])

	print("-" * 50)
	print("  Security Alerts")
	print("-" * 50)
	print(f"  {C_RED}[!!]{C_RESET} = Critical (red)    {C_YELLOW}[!]{C_RESET} = Notable (yellow)    {C_BLUE}[*]{C_RESET} = Info (blue)")
	print(f"  {C_MAGENTA}[?]{C_RESET}  = Investigate (magenta)    {C_CYAN}[H]{C_RESET} = Hidden correlation (cyan)")
	print(f"  Attack recommendations shown in {C_RED}red{C_RESET}    WPS warnings shown in {C_YELLOW}orange{C_RESET}")
	print(f"  MFP: Required = Deauth blocked    MFP: Capable/Disabled = Deauth viable")
	print()

	current_priority = None
	priority_labels = {1: "CRITICAL", 2: "NOTABLE", 3: "INFORMATIONAL"}

	for priority, message in alerts:
		if priority != current_priority:
			current_priority = priority
			label = priority_labels.get(priority, "OTHER")
			label_colors = {1: C_RED, 2: C_YELLOW, 3: C_BLUE}
			lc = label_colors.get(priority, C_RESET)
			print(f"  ── {lc}{C_BOLD}{label}{C_RESET} {'─' * (40 - len(label))}")
			print()
		print(message)
		print()

	probing = [c for c in clients if "(not associated)" in c["bssid"] and c["probes"]]
	if probing:
		print(f"  ── {C_MAGENTA}{C_BOLD}INVESTIGATE{C_RESET} {'─' * 29}")
		print()
		for c in probing:
			cv = lookup_vendor(c['mac'], oui_db)
			print(f"  {C_MAGENTA}[?]  {c['mac']}{C_RESET} ({cv})")
			print(f"       {C_MAGENTA}→ Probing: {c['probes']}{C_RESET}")
			print()

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="AirScope — Wireless Recon Parser made by yours truly")
	parser.add_argument("--version", action="version", version=f"AirScope v{VERSION}")
	parser.add_argument("file", help="Airodump-ng CSV file to parse")
	parser.add_argument("--has-clients", action="store_true", help="Only show APs with connected clients")
	parser.add_argument("--wpa2-only", action="store_true", help="Only show WPA2-PSK networks")
	parser.add_argument("--transition", action="store_true", help="Only show WPA3/WPA2 transition mode networks")
	parser.add_argument("--enterprise", action="store_true", help="Only show enterprise (MGT) networks")
	parser.add_argument("--alerts-only", action="store_true", help="Only show security alerts, skip AP listing")
	parser.add_argument("--show-bssid", action="store_true", help="Include BSSID in alert output")
	parser.add_argument("--output", help="Export results to a text file (e.g. --output report.txt)")
	parser.add_argument("--pcap", help="PCAP file to enrich AP data with RSN/MFP details")
	parser.add_argument("--show-clients", action="store_true", help="Show connected client details in alerts")
	parser.add_argument("--target", help="Show detailed info for AP by SSID name")
	parser.add_argument("--hidden", action="store_true", help="Show hidden SSID correlation — only APs where a likely SSID was identified. Combine with --alerts-only or --target.")
	parser.add_argument("--hidden-all", action="store_true", help="Like --hidden, but also shows hidden APs with no associated clients (dead ends included). Use when you want the full hidden AP inventory.")
	parser.add_argument("--pmkid", action="store_true", help="Only show APs where a PMKID was captured. Requires --pcap. Use to quickly identify clientless crack targets.")

	args = parser.parse_args()

	aps, clients = parse_airodump(args.file)
	oui_db = load_oui()

	# Apply filters
	filtered = aps

	# Sort by signal strength (strongest first)
	filtered.sort(key=lambda ap: int(ap["power"]) if ap["power"].lstrip('-').isdigit() else -100, reverse=True)

	if args.has_clients:
		filtered = [ap for ap in filtered if any(c["bssid"] == ap["bssid"] for c in clients)]

	if args.wpa2_only:
		filtered = [ap for ap in filtered if "WPA2" in ap["encryption"] and "WPA3" not in ap["encryption"]]

	if args.transition:
		filtered = [ap for ap in filtered if "SAE" in ap["auth"] and "PSK" in ap["auth"]]

	if args.enterprise:
		filtered = [ap for ap in filtered if "MGT" in ap["auth"]]

	if args.pcap:
		filtered = enrich_from_pcap(args.pcap, filtered)

	if args.pmkid:
		filtered = [ap for ap in filtered if ap.get("pmkid")]

	# Capture output if exporting
	if args.output:
		import io
		buffer = io.StringIO()
		original_stdout = sys.stdout

		class DualOutput:
			def __init__(self, stdout, buffer):
				self.stdout = stdout
				self.buffer = buffer
			def write(self, text):
				self.stdout.write(text)
				self.buffer.write(text)
			def flush(self):
				self.stdout.flush()

		sys.stdout = DualOutput(original_stdout, buffer)

	# Determine what to show based on flag combinations
	hidden_mode = args.hidden or args.hidden_all

	# If --pmkid filter produced no results, say so and exit cleanly
	if args.pmkid and not filtered:
		print("  No APs with captured PMKIDs found in this scan.")
	else:
		if args.target:
			# --target: always show target info
			display_target(filtered, clients, args.target, oui_db)
		elif not args.alerts_only and not hidden_mode:
			# Default: show full AP list and summary
			display_results(filtered, clients, oui_db)
			display_stats(filtered, clients)

		# Show alerts unless we're in hidden-only mode (without alerts-only pairing)
		if not args.target and not hidden_mode:
			display_alerts(filtered, clients, args.show_bssid, oui_db, args.show_clients)
		elif not args.target and hidden_mode and args.alerts_only:
			# --hidden/--hidden-all paired with --alerts-only
			display_alerts(filtered, clients, args.show_bssid, oui_db, args.show_clients)

		# Show hidden correlation if requested
		if hidden_mode:
			hidden_findings = correlate_hidden_ssids(filtered, clients)
			if hidden_findings:
				display_hidden_correlation(hidden_findings, oui_db, show_all=args.hidden_all)

	# Save to file if requested
	if args.output:
		sys.stdout = original_stdout
		with open(args.output, 'w', encoding='utf-8') as f:
			f.write(buffer.getvalue())
		print(f"Results exported to: {args.output}")