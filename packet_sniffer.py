from scapy.all import sniff, conf
from feature_extractor import extract_features
import json

def save_packet(packet):
    features = extract_features(packet)
    with open("packets.json", "a") as f:
        f.write(json.dumps(features) + "\n")

try:
    sniff(filter="ip", prn=save_packet, count=100)
except RuntimeError as e:
    print("Error: ", e)
    print("Ensure that WinPcap or Npcap is properly installed on your system.")
    print("Download Npcap from: https://nmap.org/npcap/")