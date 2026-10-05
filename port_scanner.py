import argparse
import collections
import concurrent.futures
import errno
import ipaddress
import random
import socket
import ssl
from typing import Optional, Dict, Any, Tuple, Union

import pyfiglet
from cryptography import x509
from scapy.all import IP, IPv6, TCP, sr1, send, conf

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

# TCP flag bits (RFC 793)
TCP_SYN, TCP_RST, TCP_ACK = 0x02, 0x04, 0x10

def guess_os(ttl: int) -> str:
    # Each OS starts packets with a default TTL (64 Linux/Unix, 128 Windows,
    # 255 network gear) and every router hop decrements it by one.
    return "Linux/Unix" if ttl <= 64 else "Windows" if ttl <= 128 else "Other"

def can_use_raw_sockets() -> bool:
    # Raw packets need root (or CAP_NET_RAW on Linux). Trying to open a raw
    # socket is more reliable than checking the UID, e.g. inside containers.
    try:
        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP).close()
        return True
    except OSError:
        return False

def syn_probe(target: str, port: int, timeout: float, is_ipv6: bool) -> Tuple[str, Optional[int]]:
    # Half-open (SYN) scan with scapy: the handshake is never completed, so the
    # service never sees a connection. Returns the port state and the reply TTL.
    # IPv6 calls the TTL field "Hop Limit" (hlim), but it means the same.
    ip_layer = IPv6 if is_ipv6 else IP
    sport = random.randint(1024, 65535)
    reply = sr1(ip_layer(dst=target)/TCP(sport=sport, dport=port, flags="S"), timeout=timeout, verbose=0)

    # No reply at all, or an ICMP error instead of TCP: a firewall is in the way
    if reply is None or not reply.haslayer(TCP):
        return "filtered", None

    ttl = reply[IPv6].hlim if is_ipv6 else reply[IP].ttl
    flags = int(reply[TCP].flags)
    if flags & (TCP_SYN | TCP_ACK) == (TCP_SYN | TCP_ACK):
        # SYN-ACK: open. Abort with a RST instead of the final ACK. Its sequence
        # number must be the one the target expects (the ACK it just sent).
        send(ip_layer(dst=target)/TCP(sport=sport, dport=port, flags="R", seq=reply[TCP].ack), verbose=0)
        return "open", ttl
    if flags & TCP_RST:
        return "closed", ttl
    return "filtered", None

def connect_probe(target: str, port: int, timeout: float, is_ipv6: bool) -> Tuple[str, Optional[str], Optional[Dict[str, str]]]:
    # Full TCP Connect Scan. The same socket is kept open for the banner grab,
    # so each open port costs one TCP connection instead of two.
    # Returns the port state, the banner and the TLS certificate details.
    banner = "No banner"
    tls_info = None

    # The address family must match the IP version or connect() fails.
    family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        err = s.connect_ex((target, port))
        if err != 0:
            # ECONNREFUSED means the host answered with a RST: it is reachable
            # but nothing listens there (closed). A timeout or an ICMP
            # unreachable means something dropped the SYN (filtered).
            state = "closed" if err == errno.ECONNREFUSED else "filtered"
            return state, None, None

        # Grab the service banner over the already established connection
        conn = s
        try:
            if port in TLS_PORTS:
                # Upgrade the same TCP connection to TLS before sending HTTP
                conn = TLS_CONTEXT.wrap_socket(s, server_hostname=target)
                tls_info = get_tls_info(conn)
            if port in [80, 443, 8080, 8443]:
                host = f"[{target}]" if is_ipv6 else target  # RFC 3986: IPv6 literals go in brackets
                conn.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
            banner_bytes = conn.recv(1024)
            if banner_bytes:
                banner = banner_bytes.decode('utf-8', errors='ignore').strip().replace('\r\n', ' ')
        except (socket.timeout, ConnectionResetError, ssl.SSLError, OSError):
            pass  # We ignore if the port rejects us when sending strange payloads
        finally:
            conn.close()  # wrap_socket detaches s, so the TLS socket must be closed explicitly

    return "open", banner, tls_info

def scan_target(ip: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address], port: int, timeout: float, scan_type: str = "connect") -> Dict[str, Any]:
    # Scans a port with the chosen technique and returns its result record.
    target = str(ip)
    is_ipv6 = ipaddress.ip_address(target).version == 6
    os_type = banner = tls_info = vuln = None

    if scan_type == "syn":
        # The OS guess reuses the TTL of the SYN-ACK, so no extra packet is
        # needed. There is no banner because no connection is ever opened.
        state, ttl = syn_probe(target, port, timeout, is_ipv6)
        if state == "open":
            os_type = guess_os(ttl)
            banner = "No banner (SYN scan)"
    else:
        # The kernel hides the TTL of connect() replies, so the OS can only be
        # estimated in SYN mode.
        state, banner, tls_info = connect_probe(target, port, timeout, is_ipv6)
        if state == "open":
            os_type = "Unknown (needs -s syn)"

    if state == "open":
        vuln = check_vulnerabilities(banner)
        endpoint = f"[{target}]:{port}" if is_ipv6 else f"{target}:{port}"
        print(f"[+] {endpoint} | {os_type} | {' '.join(banner.split())[:40]}...")
        if tls_info:
            print(f"    [TLS] Subject: {tls_info['subject']} | Issuer: {tls_info['issuer']} | Expires: {tls_info['expires']}")
        if vuln: print(f"    [!] ALERT: {vuln}")

    return {"ip": target, "port": port, "state": state, "os": os_type, "banner": banner, "tls": tls_info, "vulnerability": vuln}

MAX_ROWS_PER_STATE = 10

def print_summary(results: list) -> None:
    # Threads finish in any order, so results are sorted by IP and port
    # before printing. ip_address() sorts numerically (10.0.0.2 < 10.0.0.10),
    # and the version goes first because IPv4 and IPv6 can't be compared.
    def sort_key(r):
        addr = ipaddress.ip_address(r["ip"])
        return (addr.version, addr, r["port"])

    # Like nmap's "Not shown" line, a non-open state with many ports is
    # collapsed into a counter so a 1-1024 scan doesn't print 1000 rows.
    counts = collections.Counter(r["state"] for r in results)
    hidden = [s for s in ("closed", "filtered") if counts[s] > MAX_ROWS_PER_STATE]

    rows = sorted((r for r in results if r["state"] not in hidden), key=sort_key)
    if rows:
        ip_width = max(len("IP"), *(len(r["ip"]) for r in rows))
        print(f"\n{'IP':<{ip_width}}  {'PORT':>5}  {'STATE':<8}  {'OS':<28}  BANNER")
        for r in rows:
            banner = ' '.join((r["banner"] or "").split())[:40]
            print(f"{r['ip']:<{ip_width}}  {r['port']:>5}  {r['state']:<8}  {r['os'] or '-':<28}  {banner}")
    if hidden:
        print("Not shown: " + ", ".join(f"{counts[s]} {s} ports" for s in hidden))

def main() -> None:
    # Main entry point: argument parsing and concurrent thread execution
    print_bloodhound_banner()
    parser = argparse.ArgumentParser(description="INFOSCANN: The Network Bloodhound")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--ports", default="22,80,443")
    parser.add_argument("-m", "--mode", choices=["stealth", "aggressive"], default="stealth")
    parser.add_argument("-s", "--scan-type", choices=["connect", "syn"], default="connect",
                        help="connect: full TCP handshake (no privileges needed). "
                             "syn: half-open scan with raw packets (needs root)")
    args = parser.parse_args()

    if args.scan_type == "syn" and not can_use_raw_sockets():
        print("[!] SYN scan needs root/Administrator privileges. Falling back to connect scan.")
        args.scan_type = "connect"

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
                # getaddrinfo understands IPv6 literals and AAAA records;
                # gethostbyname only returns IPv4 addresses.
                addr_info = socket.getaddrinfo(args.target, None, proto=socket.IPPROTO_TCP)
                resolved_ip = addr_info[0][4][0]
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
                futures.append(executor.submit(scan_target, ip, p, timeout, args.scan_type))
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    print_summary(results)
    counts = collections.Counter(r["state"] for r in results)
    print(f"{'-'*60}\n[*] Hunt finished. {counts['open']} open, "
          f"{counts['closed']} closed, {counts['filtered']} filtered.")

if __name__ == "__main__":
    main()