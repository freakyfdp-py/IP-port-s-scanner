from random import randint
from ipaddress import ip_address
import os
import socket
import subprocess
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

existing_ips = set()
known_port_ips = set()
online_ips = []
port_counts = {}

BLACKLISTED_FILE = "blacklisted.txt"

def load_known_port_ips():
    for file in os.listdir('.'):
        if file.startswith('port_') and file.endswith('.txt'):
            with open(file, 'r') as f:
                for line in f:
                    known_port_ips.add(line.strip())

def load_blacklist_words():
    if not os.path.exists(BLACKLISTED_FILE):
        return set()
    with open(BLACKLISTED_FILE, 'r') as f:
        return set(line.strip().lower() for line in f if line.strip())

def generate_ip():
    while True:
        ip = f"{randint(0, 255)}.{randint(0, 255)}.{randint(0, 255)}.{randint(0, 255)}"
        try:
            ip_address(ip)
        except ValueError:
            continue
        if ip not in existing_ips and ip not in known_port_ips:
            existing_ips.add(ip)
            return ip

def is_ip_online(ip):
    command = ["ping", "-n", "1", ip]
    try:
        response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return "TTL=" in response.stdout
    except:
        return False

def check_port(ip, port, blacklist):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        if sock.connect_ex((ip, port)) != 0:
            return
        try:
            if port in (80, 443, 8080):
                protocol = "https" if port == 443 else "http"
                url = f"{protocol}://{ip}"
                response = requests.get(url, timeout=2)
                content = response.text.lower()
                for word in blacklist:
                    if word in content:
                        with open('blacklisted_hits.txt', 'a') as bfile:
                            bfile.write(f"{ip}:{port} - matched word: '{word}'\n")
                        return  # Skip saving this IP
        except:
            return  # Couldn't fetch or parse, skip

        port_counts[port] = port_counts.get(port, 0) + 1
        with open(f'port_{port}.txt', 'a') as f:
            f.write(ip + '\n')
        with open('valid_ips.txt', 'a') as f:
            f.write(ip + '\n')

def run_scan():
    load_known_port_ips()
    blacklist_words = load_blacklist_words()

    try:
        amount = int(input("How many IPs do you want to generate >> "))
    except ValueError:
        print("Invalid number.")
        return

    ports_input = input("What ports do you want to check (e.g. 80 443 8080) >> ")
    try:
        ports = [int(p) for p in ports_input.split()]
    except ValueError:
        print("Invalid ports.")
        return

    print("[*] Generating IPs...")
    for _ in range(amount):
        generate_ip()

    print("[*] Pinging IPs...")
    with ThreadPoolExecutor(max_workers=256) as executor:
        ping_futures = {executor.submit(is_ip_online, ip): ip for ip in existing_ips}
        for future in as_completed(ping_futures):
            ip = ping_futures[future]
            if future.result():
                online_ips.append(ip)

    print(f"[*] Found {len(online_ips)} online IPs.")

    print("[*] Scanning ports...")
    with ThreadPoolExecutor(max_workers=256) as executor:
        futures = [
            executor.submit(check_port, ip, port, blacklist_words)
            for ip in online_ips for port in ports
        ]
        for future in as_completed(futures):
            future.result()

    print(f"[*] Scan complete.")
    for port, count in port_counts.items():
        print(f"Port {port}: {count} open")

if __name__ == "__main__":
    run_scan()
    input('Press enter to quit...')
