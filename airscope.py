import csv
import sys
import argparse
from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt

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

def parse_airodump(filepath):

	print("AirScope starting...")

def parse_airodump(filepath):
    """Parse airodump-ng CSV into APs and clients"""
    aps = []
    clients = []
    section = None

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()

            # Detect which section we're in by the header
            if line.startswith("BSSID, First time seen"):
                section = "ap"
                continue
            elif line.startswith("Station MAC"):
                section = "client"
                continue

            # Skip blank lines
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
	return aps

def display_results(aps, clients, oui_db):
    """Print a clean recon summary"""
    print("=" * 50)
    print("  AirScope — Wireless Recon Summary")
    print("=" * 50)
    print()

    for i, ap in enumerate(aps, 1):
        # Find clients connected to this AP
        ap_clients = [c for c in clients if c["bssid"] == ap["bssid"]]

        print(f"[{i}] {ap['essid']}")
        vendor = lookup_vendor(ap['bssid'], oui_db)
        print(f"    BSSID:    {ap['bssid']} ({vendor})")
        freq = CHANNEL_FREQ.get(ap['channel'], "?")
        print(f"    Channel:  {ap['channel']} ({freq} MHz)")
        print(f"    Encrypt:  {ap['encryption']} {ap['cipher']} {ap['auth']}")
        print(f"    Clients:  {len(ap_clients)}")

        for c in ap_clients:
            print(f"              └─ {c['mac']} ({lookup_vendor(c['mac'], oui_db)})")
            if c["probes"]:
                print(f"                 Probes: {c['probes']}")

        print()

def display_stats(aps, clients):
	"""Print Summaary Statistics"""
	
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
      
def display_alerts(aps, clients, show_bssid=False, oui_db={}):
	"""Flag security weaknesses, sorted by priority"""
	
	alerts = []
	
	for ap in aps:
		vendor = lookup_vendor(ap["bssid"], oui_db)
		name = ap["essid"] if ap["essid"] else "Hidden (" + ap["bssid"] + ")"
		vendor_line = f"\n       └─ Vendor: {vendor}" if vendor != "Unknown vendor" else ""
		enc = ap["encryption"]
		auth = ap["auth"]
		ch = ap["channel"]
		freq = CHANNEL_FREQ.get(ch, "?")
		ap_clients = [c for c in clients if c["bssid"] == ap["bssid"]]
		cl = len(ap_clients)
		mfp = ap.get("mfp", "Unknown — verify in Wireshark")
		
		bssid_info = f" [{ap['bssid']}]" if show_bssid else ""
		vendor = lookup_vendor(ap["bssid"], oui_db)
		vendor_line = f"\n       └─ Vendor: {vendor}" if vendor != "Unknown vendor" else ""
		wps_flag = " | WPS: ENABLED → Pixie Dust / Reaver" if ap.get("wps") else ""
		
		if "OPN" in enc:
			alerts.append((1, f"  [!!] {name}{bssid_info} (ch:{ch}/{freq}MHz) — OPEN → Evil twin / sniffing{vendor_line}"))
		elif "WPA" in enc and "WPA2" not in enc:
			alerts.append((1, f"  [!!] {name}{bssid_info} (ch:{ch}/{freq}MHz) — Legacy WPA → Capture + crack{wps_flag}{vendor_line}"))
		elif "SAE" in auth and "PSK" in auth:
			alerts.append((2, f"  [!]  {name}{bssid_info} (ch:{ch}/{freq}MHz), (cl:{cl}) — Transition → Downgrade | MFP: {mfp}{wps_flag}{vendor_line}"))
		elif "SAE" in auth:
			alerts.append((2, f"  [!]  {name}{bssid_info} (ch:{ch}/{freq}MHz), (cl:{cl}) — SAE Solo → Wacker / Evil twin | MFP: {mfp}{vendor_line}"))
		elif "MGT" in auth:
			alerts.append((3, f"  [*]  {name}{bssid_info} (ch:{ch}/{freq}MHz), (cl:{cl}) — Enterprise → Fake RADIUS{vendor_line}"))
		elif "WPA2" in enc and "PSK" in auth and ap.get("wps"):
			alerts.append((2, f"  [!]  {name}{bssid_info} (ch:{ch}/{freq}MHz), (cl:{cl}) — WPA2-PSK + WPS ENABLED → Pixie Dust / Reaver{vendor_line}"))
	
	# Sort by priority number — 1 first, 3 last
	alerts.sort(key=lambda x: x[0])
	
	print("-" * 50)
	print("  Security Alerts")
	print("-" * 50)
	print("  ch = Channel | cl = Connected Clients")
	print("  [!!] = Critical  [!] = Notable  [*] = Info  [?] = Investigate")
	print("  MFP: Required = Deauth blocked | Capable/Disabled = Deauth viable")

	print()
	
	for priority, message in alerts:
		print(message)
	
	print()
	
	# Probing clients - one line each
	probing = [c for c in clients if "(not associated)" in c["bssid"] and c["probes"]]
	if probing:
		print("-" * 50)
		print("  Probing Clients")
		print("-" * 50)
		for c in probing:
			cv = lookup_vendor(c['mac'], oui_db)
			print(f"  [?]  {c['mac']} ({cv}) → Probing: {c['probes']}")
	
	print()

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="AirScope — Wireless Recon Parser made by yours truly")
	parser.add_argument("file", help="Airodump-ng CSV file to parse")
	parser.add_argument("--has-clients", action="store_true", help="Only show APs with connected clients")
	parser.add_argument("--wpa2-only", action="store_true", help="Only show WPA2-PSK networks")
	parser.add_argument("--transition", action="store_true", help="Only show WPA3/WPA2 transition mode networks")
	parser.add_argument("--enterprise", action="store_true", help="Only show enterprise (MGT) networks")
	parser.add_argument("--alerts-only", action="store_true", help="Only show security alerts, skip AP listing")
	parser.add_argument("--show-bssid", action="store_true", help="Include BSSID in alert output")
	parser.add_argument("--output", help="Export results to a text file (e.g. --output report.txt)")
	parser.add_argument("--pcap", help="PCAP file to enrich AP data with RSN/MFP details")
	parser.add_argument("--freq", action="store_true", help="Show frequency alongside channel number")

	args = parser.parse_args()
	
	aps, clients = parse_airodump(args.file)
	oui_db = load_oui()
	
	# Apply filters
	filtered = aps
	
	if args.has_clients:
		filtered = [ap for ap in filtered if any(c["bssid"] == ap["bssid"] for c in clients)]
	
	if args.wpa2_only:
		filtered = [ap for ap in filtered if "WPA2" in ap["encryption"] and "WPA3" not in ap["encryption"]]
	
	if args.transition:
		filtered = [ap for ap in filtered if "SAE" in ap["auth"] and "PSK" in ap["auth"]]
	
	# Enrich with PCAP data if provided
	if args.enterprise:
		filtered = [ap for ap in filtered if "MGT" in ap["auth"]]

	if args.pcap:
		filtered = enrich_from_pcap(args.pcap, filtered)
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
	
	if not args.alerts_only:
		display_results(filtered, clients, oui_db)
		display_stats(filtered, clients)
	
	display_alerts(filtered, clients, args.show_bssid, oui_db)
	
	# Save to file if requested
	if args.output:
		sys.stdout = original_stdout
		with open(args.output, 'w', encoding='utf-8') as f:
			f.write(buffer.getvalue())
		print(f"Results exported to: {args.output}")
