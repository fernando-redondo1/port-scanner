import argparse
import concurrent.futures
import ipaddress
import random
import socket
import ssl
from typing import Optional, Dict, Any, Union

import pyfiglet
from cryptography import x509
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

# Ports where the service speaks TLS from the first byte
TLS_PORTS = {443, 8443}

# A scanner must talk to any server, including self-signed or expired ones,
# so certificate and hostname verification are disabled on purpose.
TLS_CONTEXT = ssl.create_default_context()
TLS_CONTEXT.check_hostname = False
TLS_CONTEXT.verify_mode = ssl.CERT_NONE

def get_tls_info(tls_sock: ssl.SSLSocket) -> Optional[Dict[str, str]]:
    # Extracts subject, issuer and expiry date from the server certificate.
    # With CERT_NONE, getpeercert() returns an empty dict, so the raw DER
    # certificate is requested and parsed with the cryptography library.
    der = tls_sock.getpeercert(binary_form=True)
    if not der:
        return None
    cert = x509.load_der_x509_certificate(der)
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "expires": cert.not_valid_after_utc.isoformat(),
    }

def scan_target(ip: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address], port: int, timeout: float) -> Optional[Dict[str, Any]]:
    # Scans a port, grabs its banner and uses TTL to estimate the OS.
    target = str(ip)
    banner = "No banner"
    tls_info = None

    # 1. Standard TCP Connect Scan. The same socket is kept open for the banner
    # grab, so each open port costs one TCP connection instead of two.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((target, port)) != 0:
            return None

        # 2. Grab the service banner over the already established connection
        conn = s
        try:
            if port in TLS_PORTS:
                # Upgrade the same TCP connection to TLS before sending HTTP
                conn = TLS_CONTEXT.wrap_socket(s, server_hostname=target)
                tls_info = get_tls_info(conn)
            if port in [80, 443, 8080, 8443]:
                conn.sendall(f"HEAD / HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
            banner_bytes = conn.recv(1024)
            if banner_bytes:
                banner = banner_bytes.decode('utf-8', errors='ignore').strip().replace('\r\n', ' ')
        except (socket.timeout, ConnectionResetError, ssl.SSLError, OSError):
            pass  # We ignore if the port rejects us when sending strange payloads
        finally:
            conn.close()  # wrap_socket detaches s, so the TLS socket must be closed explicitly

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
    if tls_info:
        print(f"    [TLS] Subject: {tls_info['subject']} | Issuer: {tls_info['issuer']} | Expires: {tls_info['expires']}")
    if vuln: print(f"    [!] ALERT: {vuln}")

    return {"ip": target, "port": port, "os": os_type, "banner": banner, "tls": tls_info, "vulnerability": vuln}

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