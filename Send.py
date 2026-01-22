import socket
import json
import random
import os
import hmac
import hashlib
from scapy.all import *

PI_HOST_IPv6 = "fd53:aaaa:bbb:5:da3a:ddff:fea4:c04a"
PI_HOST_MAC = "D8:3A:DD:A4:C0:4A"
PI_CONTROL_PORT = 13344

MY_IFACE = "Ethernet" 
MY_MAC = "2C:58:B9:8B:4E:24"
MY_IPv6 = "fd53:aaaa:bbb:5::10"

SPOOFED_MAC = "2C:58:B9:8B:4E:25"
SPOOFED_IPv6 = "fd53:aaaa:bbb:5::bad1"

SHARED_SECRET_KEY = b"8cf39598082ef29891b894673da656e2c008ff8e2023b13903c8c909784aa463"

def send_structured_payload(payload_json, s_mac, s_ipv6):
    payload_str = json.dumps(payload_json, sort_keys=True).encode('utf-8')
    signature = hmac.new(SHARED_SECRET_KEY, payload_str, hashlib.sha256).hexdigest()
    final_package = json.dumps({"payload": payload_json, "signature": signature}).encode('utf-8')

    if s_mac == MY_MAC and s_ipv6 == MY_IPv6:
        try:
            print(f"--- Sending REAL command via Standard Socket ---")
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((PI_HOST_IPv6, PI_CONTROL_PORT))
            sock.sendall(final_package)
            sock.close()
            print("✅ Command executed successfully.")
        except Exception as e:
            print(f"❌ Connection failed: {e}")

    else:
        try:
            print(f"--- Sending SPOOFED packet via Scapy (Firewall Test) ---")
            ether = Ether(src=s_mac, dst=PI_HOST_MAC)
            ip6 = IPv6(src=s_ipv6, dst=PI_HOST_IPv6)
            tcp = TCP(sport=random.randint(1024, 65535), dport=PI_CONTROL_PORT, flags='S')
            
            packet = ether / ip6 / tcp / final_package
            sendp(packet, iface=MY_IFACE, verbose=False)
            print("🚀 Spoofed packet injected. Check 'dmesg' on Pi to see if it was DROPPED.")
        except Exception as e:
            print(f"❌ Scapy error: {e}")

def main_menu():
    while True:
        print("\n===== Remote Pi Configurator (Firewall Tester) =====")
        print("1. Get current network config")
        print("2. Set new IPv6 address")
        print("3. Set new MAC address")
        print("4. Set VLAN ID for eth0")
        print("5. Set new IPv4 address")
        print("\n--- Firewall Source Filtering Tests (should be DROPPED) ---")
        print("6. Send 'get_config' from SPOOFED MAC address")
        print("7. Send 'get_config' from SPOOFED IPv6 address")
        print("8. Send 'get_config' from BOTH SPOOFED MAC and IPv6")
        print("---------------------------------------------------------")
        print("0. Exit")
        choice = input("Enter your choice: ")
        
        payload = None
        s_mac = MY_MAC
        s_ipv6 = MY_IPv6
        
        if choice == '1':
            payload = {"command": "get_config", "params": {"iface": "eth0.7"}}
        elif choice == '2':
            ip = input("  Enter new IPv6 address: ")
            payload = {"command": "set_ipv6", "params": {"ip": ip}}
        elif choice == '3':
            mac = input("  Enter new MAC address: ")
            payload = {"command": "set_mac", "params": {"mac": mac}}
        elif choice == '4':
            try:
                vlan_id = int(input("  Enter new VLAN ID: "))
                payload = {"command": "set_vlan", "params": {"vlan_id": vlan_id, "rm_vlan": []}}
            except: continue
        elif choice == '5':
            ip = input("  Enter new IPv4 address: ")
            payload = {"command": "set_ipv4", "params": {"ip": ip, "prefix": 24}}
        elif choice == '6':
            payload = {"command": "get_config", "params": {"iface": "eth0.7"}}
            s_mac = SPOOFED_MAC
        elif choice == '7':
            payload = {"command": "get_config", "params": {"iface": "eth0.7"}}
            s_ipv6 = SPOOFED_IPv6
        elif choice == '8':
            payload = {"command": "get_config", "params": {"iface": "eth0.7"}}
            s_mac = SPOOFED_MAC
            s_ipv6 = SPOOFED_IPv6
        elif choice == '0':
            break
        else:
            print("Invalid choice.")
            continue
            
        if payload:
            send_structured_payload(payload, s_mac, s_ipv6)

if __name__ == "__main__":
    main_menu()