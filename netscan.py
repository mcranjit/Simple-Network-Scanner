from scapy.all import ARP, Ether, srp
import socket
from tqdm import tqdm

def scan(ip_range):
    print(f"Scanning network: {ip_range}...")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def scan_ports(ip, ports=list(range(1, 1025))):  
    open_ports = []
    print(f"\n🔍 Scanning ports on {ip}...")
    for port in tqdm(ports, desc=f"Scanning {ip}", leave=False):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports


def print_result(devices):
    print("\nDevices Found:")
    print("IP Address\t\tMAC Address")
    print("-" * 40)
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

target_range = "192.168.12.13/24"
scanned_devices = scan(target_range)
print_result(scanned_devices)
print("\nScanning open ports on each device...")

for device in scanned_devices:
    ip = device['ip']
    ports = scan_ports(ip)
    if ports:
        print(f"[+] {ip} has open ports: {ports}")
    else:
        print(f"[-] {ip} has no common open ports.")

