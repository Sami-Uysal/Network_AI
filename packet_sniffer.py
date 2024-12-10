from scapy.all import sniff
from feature_extractor import extract_features
import json

def classify_packet(packet):

    return 1 if "malicious_condition" in str(packet) else 0 

def save_packet(packet):
    features = extract_features(packet)

    features['label'] = classify_packet(packet)

    with open("packets.json", "a") as f:
        f.write(json.dumps(features) + "\n")

try:
    sniff(filter="ip", prn=save_packet, count=100)
except RuntimeError as e:
    print("Error: ", e)
    print("Ensure that WinPcap or Npcap is properly installed on your system.")
    print("Download Npcap from: https://nmap.org/npcap/")
