import csv
import sys
import argparse

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

def display_results(aps, clients):
    """Print a clean recon summary"""
    print("=" * 50)
    print("  AirScope — Wireless Recon Summary")
    print("=" * 50)
    print()

    for i, ap in enumerate(aps, 1):
        # Find clients connected to this AP
        ap_clients = [c for c in clients if c["bssid"] == ap["bssid"]]

        print(f"[{i}] {ap['essid']}")
        print(f"    BSSID:    {ap['bssid']}")
        print(f"    Channel:  {ap['channel']}")
        print(f"    Encrypt:  {ap['encryption']} {ap['cipher']} {ap['auth']}")
        print(f"    Clients:  {len(ap_clients)}")

        for c in ap_clients:
            print(f"              └─ {c['mac']}")
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
      
def display_alerts(aps, clients, show_bssid=False):
	"""Flag security weaknesses, sorted by priority"""
	
	alerts = []
	
	for ap in aps:
		name = ap["essid"] if ap["essid"] else "Hidden (" + ap["bssid"] + ")"
		enc = ap["encryption"]
		auth = ap["auth"]
		ch = ap["channel"]
		ap_clients = [c for c in clients if c["bssid"] == ap["bssid"]]
		cl = len(ap_clients)
		
		bssid_info = f" [{ap['bssid']}]" if show_bssid else ""
		
		if "OPN" in enc:
			alerts.append((1, f"  [!!] {name}{bssid_info} (ch:{ch}) — OPEN → Evil twin / sniffing"))
		elif "WPA" in enc and "WPA2" not in enc:
			alerts.append((1, f"  [!!] {name}{bssid_info} (ch:{ch}) — Legacy WPA → Capture + crack"))
		elif "SAE" in auth and "PSK" in auth:
			alerts.append((2, f"  [!]  {name}{bssid_info} (ch:{ch}), (cl:{cl}) — Transition → Downgrade attack (verify MFP)"))
		elif "SAE" in auth:
			alerts.append((2, f"  [!]  {name}{bssid_info} (ch:{ch}), (cl:{cl}) — SAE Solo → Wacker / Evil twin"))
		elif "MGT" in auth:
			alerts.append((3, f"  [*]  {name}{bssid_info} (ch:{ch}), (cl:{cl}) — Enterprise → Fake RADIUS"))
	
	# Sort by priority number — 1 first, 3 last
	alerts.sort(key=lambda x: x[0])
	
	print("-" * 50)
	print("  Security Alerts")
	print("-" * 50)
	print("  ch = Channel | cl = Connected Clients")
	print("  [!!] = Critical  [!] = Notable  [*] = Info  [?] = Investigate")
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
			print(f"  [?]  {c['mac']} → Probing: {c['probes']}")
	
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

	args = parser.parse_args()
	
	aps, clients = parse_airodump(args.file)
	
	# Apply filters
	filtered = aps
	
	if args.has_clients:
		filtered = [ap for ap in filtered if any(c["bssid"] == ap["bssid"] for c in clients)]
	
	if args.wpa2_only:
		filtered = [ap for ap in filtered if "WPA2" in ap["encryption"] and "WPA3" not in ap["encryption"]]
	
	if args.transition:
		filtered = [ap for ap in filtered if "SAE" in ap["auth"] and "PSK" in ap["auth"]]
	
	if args.enterprise:
		filtered = [ap for ap in filtered if "MGT" in ap["auth"]]
	
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
		display_results(filtered, clients)
		display_stats(filtered, clients)
	
	display_alerts(filtered, clients, args.show_bssid)
	
	# Save to file if requested
	if args.output:
		sys.stdout = original_stdout
		with open(args.output, 'w', encoding='utf-8') as f:
			f.write(buffer.getvalue())
		print(f"Results exported to: {args.output}")
