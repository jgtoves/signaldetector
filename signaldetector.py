from scapy.all import *
from datetime import datetime

# Define the "High Voltage" threshold
# -30 is very strong/close, -90 is very weak/far
THRESHOLD = -45 

def detect_high_rssi(pkt):
    # We look for 802.11 Beacon frames (Type 0, Subtype 8)
    if pkt.haslayer(Dot11Beacon):
        # Extract the Signal Strength (RSSI)
        try:
            rssi = pkt.dBm_AntSignal
            bssid = pkt.addr2 # The Hardware MAC address
            ssid = pkt.info.decode('utf-8', errors='ignore') or "HIDDEN"
            
            # Logic: If the signal is too strong, it's a proximity threat
            if rssi > THRESHOLD:
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"\n[!!!] HIGH RSSI ALERT [!!!]")
                print(f"TIME: {timestamp}")
                print(f"SIGNAL: {rssi} dBm (EXTREMELY CLOSE)")
                print(f"DEVICE ID (BSSID): {bssid}")
                print(f"NAME (SSID): {ssid}")
                print(f"--- Possible Proximity Device/IMSI Catcher ---")
                
        except AttributeError:
            # Some packets might not have the RSSI attribute
            pass

print("--- SOVEREIGN SIGNAL MONITOR ACTIVE ---")
print(f"[*] Scanning for signals stronger than {THRESHOLD} dBm...")
print("[*] Press Ctrl+C to stop.")

# Start sniffing on your wireless interface (usually 'en0' on MacBook)
# Use monitor=True if your card supports it to see ALL traffic
try:
    sniff(iface="en0", prn=detect_high_rssi, store=0)
except PermissionError:
    print("[!] Error: You must run this script with 'sudo' (Root privileges).")