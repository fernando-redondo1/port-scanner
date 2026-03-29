import argparse
import concurrent.futures
import ipaddress
import random
import socket
from typing import Optional, Dict, Any, Union

import pyfiglet
from scapy.all import IP, TCP, sr1, send, conf

# --- MODULAR IMPORTS ---
try:
    from .art import DOGS, QUOTES
except ImportError:
    # This allows running the script directly or as a package
    from art import DOGS, QUOTES

conf.verb = 0

def print_bloodhound_banner():
    """Prints the banner using the resources from art.py"""
    fonts = ["slant", "small"]
    title = pyfiglet.figlet_format("INFOSCANN", font=random.choice(fonts))
    print(title)
    print(random.choice(DOGS))
    print(f"[{random.choice(QUOTES)}]")
    print("-" * 60)

VULN_DB = {
    "apache/2.4.7": "CRITICAL: Heartbleed risk.",
    "openssh_6.6": "HIGH: Potential exploit (CVE-2016-0777).",
    "iis/7.5": "MEDIUM: Outdated Windows Server."
}

def check_vulnerabilities(banner: str) -> Optional[str]:
    # Checks if the banner version is in our list of critical vulnerabilities.
    b_low = banner.lower()
    for version, msg in VULN_DB.items():
        if version in b_low:
            return msg
    return None

def scan_target(ip: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address], port: int, timeout: float) -> Optional[Dict[str, Any]]:
    # Scans a port, grabs its banner and uses TTL to estimate the OS.
    target = str(ip)
    is_open = False
    
    # 1. Standard TCP Connect Scan
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((target, port)) == 0:
            is_open = True
            
    if not is_open:
        return None  
        
    # 2. Grab the service banner
    banner = "No banner"
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            if port in [80, 443, 8080]: 
                s.sendall(f"HEAD / HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
            banner_bytes = s.recv(1024)
            if banner_bytes:
                banner = banner_bytes.decode('utf-8', errors='ignore').strip().replace('\r\n', ' ')
    except (socket.timeout, ConnectionRefusedError, ConnectionResetError, OSError):
        pass  # We ignore if the port rejects us when sending strange payloads

    # 3. Passive OS Fingerprinting with Scapy (requires admin/root)
    os_type = "Unknown"
    try:
        pkt = IP(dst=target)/TCP(dport=port, flags="S")
        res = sr1(pkt, timeout=timeout, verbose=0)
        if res and res.haslayer(IP):
            ttl = res.getlayer(IP).ttl
            os_type = "Linux/Unix" if ttl <= 64 else "Windows" if ttl <= 128 else "Other"
            send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=0)
    except PermissionError:
        os_type = "Unknown (Require Admin/Root)"
    except Exception:
        os_type = "Unknown (Error/Loopback)"
        
    vuln = check_vulnerabilities(banner)
    print(f"[+] {target}:{port} | {os_type} | {' '.join(banner.split())[:40]}...")
    if vuln: print(f"    [!] ALERT: {vuln}")
    
    return {"ip": target, "port": port, "os": os_type, "banner": banner, "vulnerability": vuln}

def main() -> None:
    # Main entry point: argument parsing and concurrent thread execution
    print_bloodhound_banner()
    parser = argparse.ArgumentParser(description="INFOSCANN: The Network Bloodhound")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--ports", default="22,80,443")
    parser.add_argument("-m", "--mode", choices=["stealth", "aggressive"], default="stealth")
    args = parser.parse_args()

    is_agg = args.mode == "aggressive"
    workers, timeout = (100, 0.5) if is_agg else (20, 1.5)
    
    # Manual port validation
    ports = []
    for p in args.ports.split(","):
        try:
            port_num = int(p.strip())
            if 1 <= port_num <= 65535:
                ports.append(port_num)
        except ValueError:
            pass
            
    if not ports:
        print("[!] Target error: No valid ports specified.")
        return
    
    try:
        if "/" in args.target:
            net = ipaddress.ip_network(args.target, strict=False)
            targets = list(net.hosts())
        else:
            try:
                resolved_ip = socket.gethostbyname(args.target)
                targets = [ipaddress.ip_address(resolved_ip)]
            except socket.gaierror:
                print(f"[!] Target error: Could not resolve domain '{args.target}'")
                return
    except ValueError: 
        print(f"[!] Target error: Invalid IP/CIDR format '{args.target}'")
        return

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        for ip in targets:
            for p in ports:
                futures.append(executor.submit(scan_target, ip, p, timeout)) 
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r:
                results.append(r)

    print(f"{'-'*60}\n[*] Hunt finished. Found {len(results)} open ports.")

if __name__ == "__main__":
    main()