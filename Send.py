# control_client.py
import socket
import json
import random
import os
import hmac
import hashlib
from scapy.all import *

# =======================================================
# === Cấu hình Client ===
# =======================================================
PI_HOST_IPv6 = "fd53:aaaa:bbb:5:da3a:ddff:fea4:c04a"
PI_HOST_MAC = "D8:3A:DD:A4:C0:4A"
PI_CONTROL_PORT = 13344

MY_IFACE = "Ethernet"
# ĐỊA CHỈ HỢP LỆ (WHITELISTED)
MY_MAC = "2C:58:B9:8B:4E:24"
MY_IPv6 = "fd53:aaaa:bbb:5::10"

# ĐỊA CHỈ GIẢ MẠO (SPOOFED) DÙNG ĐỂ KIỂM TRA TƯỜNG LỬA
SPOOFED_MAC = "DE:AD:BE:EF:CA:FE"
SPOOFED_IPv6 = "fd53:aaaa:bbb:5::bad1"

# KHÓA BÍ MẬT - Phải giống hệt với khóa ở server
SHARED_SECRET_KEY = b"4sjqyBReJ#sja4oa"


# =======================================================
# === Hàm Gửi Lệnh (Hỗ trợ Giả mạo Nguồn) ===
# =======================================================
def send_structured_payload(payload_json):
    print(f"--- Sending command to {PI_HOST_IPv6}:{PI_CONTROL_PORT} ---")

    # Tạo chữ ký HMAC
    payload_str = json.dumps(payload_json, sort_keys=True).encode('utf-8')
    signature = hmac.new(SHARED_SECRET_KEY, payload_str, hashlib.sha256).hexdigest()
    final_package = {
        "payload": payload_json,
        "signature": signature
    }
    final_package_bytes = json.dumps(final_package).encode('utf-8')

    try:
        # Tạo socket IPv6 TCP
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

        # Timeout tránh treo
        sock.settimeout(3)

        # Kết nối server
        sock.connect((PI_HOST_IPv6, PI_CONTROL_PORT, 0, 0))

        # Gửi dữ liệu
        sock.sendall(final_package_bytes)

        print("\n--- COMMAND STATUS ---")
        print("Command sent successfully to the server.")
        print("----------------------")

    except Exception as e:
        print(f"\nAN ERROR OCCURRED: {e}")

    finally:
        try:
            sock.close()
        except:
            pass


def main_menu():
    while True:
        print("\n===== Remote Pi Configurator  =====")
        print("--- Normal Commands (from whitelisted source) ---")
        print("1. Get current network config (eth0.7)")
        print("2. Set new IPv6 address for eth0.7")
        print("3. Set new MAC address for eth0.7")
        print("4. Set VLAN ID for eth0 (0 to remove VLAN)")
        print("5. Set new IPv4 address for eth0.7")
        print("\n--- Firewall Source Filtering Tests (should be DROPPED) ---")
        print("6. Send 'get_config' from SPOOFED MAC address")
        print("7. Send 'get_config' from SPOOFED IPv6 address")
        print("8. Send 'get_config' from BOTH SPOOFED MAC and IPv6")
        print("---------------------------------------------------------")
        print("0. Exit")
        choice = input("Enter your choice: ")
        
        payload = None
        # Biến cờ để xác định xem có cần giả mạo không
        spoof_mac = False
        spoof_ipv6 = False
        
        if choice == '1':
            payload = {"command": "get_config", "params": {"iface": "eth0"}}
        elif choice == '2':
            ip = input("  Enter new IPv6 address: ")
            payload = {"command": "set_ipv6", "params": {"ip": ip}}
        elif choice == '3':
            mac = input("  Enter new MAC address: ")
            payload = {"command": "set_mac", "params": {"mac": mac}}
        elif choice == '4':
            try:
                vlan_id = int(input("  Enter new VLAN ID to add (e.g., 5, or 0 to only remove): "))
                
                # Nhập chuỗi, ví dụ: "5, 7, 10"
                rm_vlan_input = input("  Enter VLAN IDs to remove, separated by commas (e.g., 5,7,10 or leave empty): ")
                
                # Chuyển chuỗi thành mảng các số nguyên
                # Nếu người dùng để trống, rm_vlan sẽ là mảng rỗng []
                if rm_vlan_input.strip():
                    rm_vlan = [int(x.strip()) for x in rm_vlan_input.split(',')]
                else:
                    rm_vlan = []

                payload = {
                    "command": "set_vlan", 
                    "params": {
                        "vlan_id": vlan_id,
                        "rm_vlan": rm_vlan  # Gửi mảng các ID cần xóa
                    }
                }
            except ValueError:
                print("Invalid input. Please enter numbers separated by commas.")
                continue
        elif choice == '5':
            try:
                ip = input("  Enter new IPv4 address: ")
                prefix = int(input("  Enter prefix length (e.g., 24 for 255.255.255.0): "))
                payload = {"command": "set_ipv4", "params": {"ip": ip, "prefix": prefix}}
            except ValueError:
                print("Invalid Prefix. Please enter a number.")
                continue
        elif choice == '6':
            print("\n>>> CONFIGURING TEST: Send from a spoofed MAC. This should fail.")
            payload = {"command": "get_config", "params": {"iface": "eth0.7"}}
            spoof_mac = True
        elif choice == '7':
            print("\n>>> CONFIGURING TEST: Send from a spoofed IPv6. This should fail.")
            payload = {"command": "get_config", "params": {"iface": "eth0.7"}}
            spoof_ipv6 = True
        elif choice == '8':
            print("\n>>> CONFIGURING TEST: Send from a spoofed MAC & IPv6. This should fail.")
            payload = {"command": "get_config", "params": {"iface": "eth0.7"}}
            spoof_mac = True
            spoof_ipv6 = True
        elif choice == '0':
            break
        else:
            print("Invalid choice.")
            continue
            
        # Nếu payload đã được tạo, tiến hành gửi đi
        if payload:
            # Xác định địa chỉ nguồn dựa trên các cờ đã đặt
            source_mac = SPOOFED_MAC if spoof_mac else MY_MAC
            source_ipv6 = SPOOFED_IPv6 if spoof_ipv6 else MY_IPv6
            
            # Gọi hàm gửi với các địa chỉ nguồn thích hợp
            send_structured_payload(payload)

if __name__ == "__main__":
    main_menu()