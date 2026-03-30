# InfoScann 
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**InfoScann** is a fast, modular, and concurrent network port scanner built entirely in Python.

I designed this project to perform effective network reconnaissance tasks—like banner grabbing and OS fingerprinting—by leveraging an asynchronous parallelism model and low-level raw packet manipulation.

## How It Works Under the Hood

The core logic of the scanner (`port_scanner.py`) broken down into three main phases that happen sequentially for each analyzed port:

1. **Parallelism and Core Connection**: To ensure the tool is fast when scanning multiple IP addresses and ports at once, I implemented Python's `concurrent.futures.ThreadPoolExecutor`. Instead of iterating port by port in a blocking loop, the program dispatches and manages a pool of threads that run tests in parallel. The actual detection happens using low-level abstractions with the standard `socket` library (`connect_ex` method).
2. **Active Banner Grabbing**: When the scanner detects that a target's port has accepted the connection in the previous step, it immediately tries to grab the service's response (*banner*). For web services on typical ports (like 80, 443, 8080), the code manually injects a simple HTTP request (`HEAD / HTTP/1.1`) to force an identifiable response from the remote server.
3. **Passive OS Fingerprinting**: The most advanced component of the application uses the `scapy` library to craft raw packets and analyze the back-and-forth "Time-To-Live" (TTL) in the target's TCP response. Through this simple calculation on the lower layers of the OSI model, the tool makes an educated guess about the Operating System we are up against (e.g., TTL~64 usually points to Linux distributions, TTL~128 points to Windows).

## Tech Stack & Libraries

- `socket`: Used to instantiate the lowest-level TCP/IP connections.
- `concurrent.futures`: Handles the orchestration, concurrency, and volume control of execution threads.
- `scapy`: Essential for crafting and analyzing raw network packets.
- `argparse`: Integrates command-line parameters to maintain a POSIX standard experience.
- `ipaddress`: Parses and robustly identifies single IPs and allows for the breakdown of entire subnets (CIDR blocks).
- `pyfiglet`: Added as a temporary aesthetic touch to invoke a pleasant CLI interface on startup.

## Getting Started

To get all the features of the tool working at 100%, your environment needs to be properly set up:

**Prerequisites:**
- **Python 3.8** or higher.
- **Windows:** It is absolutely necessary to have **Npcap** installed and to run your console as **Administrator** (required by Scapy).
- **Linux / MacOS:** No extra drivers are needed, but the script must be executed with superuser privileges (`sudo`).

**Installation:**
The project is packaged using `pyproject.toml`, which allows you to cleanly install it as a native system command.

```bash
# While inside the code directory, install the tool via pip:
pip install .

# Once installed, you can run it from anywhere on your system:
infoscann -t 127.0.0.1 -p 80,443
```

**Using Docker (Recommended):**
The project is automatically built and published to the GitHub Container Registry. You can run it directly without installing any local dependencies:

```bash
# Note: --privileged is required for Scapy to perform OS footprinting via raw sockets
docker run --privileged ghcr.io/fernando-redondo1/port-scanner:main -t scanme.nmap.org -m stealth
```

## See It In Action

![Usage Example](screenshot.png)

### Usage Modes & Examples:
The tool allows you to adapt the aggressiveness and range of the scan based on your needs:

* **Stealth Mode (Default)**
  `infoscann -t scanme.nmap.org`

* **Aggressive Mode:**
  `infoscann -t scanme.nmap.org -m aggressive`

* **Target Specific Ports:**
  `infoscann -t 127.0.0.1 -p 21,22,80,443,8080`

## What's Next (Roadmap)

I've identified a few key areas for refactoring and improvement for production environments going forward:

- **Stealth Strategies**: The current implementation explicitly relies on completing the *"3-Way Handshake"* (TCP Connect Scan), which easily gets logged by any basic firewall. The obvious refactoring move here is to implement a *TCP SYN Scan* by sending raw packets with `scapy` that don't leave such an obvious footprint.
- **Cryptography Support (TLS/SSL)**: Right now, all connections initiating a banner grab assume plain text. Updating the logic to intercept port 443 and applying a wrapper with Python's `ssl` library will yield HTTPS certificate information from most modern web servers.
- **Vulnerability Scanner Scalability**: The passive vulnerability check currently reads from a constant block in memory. The natural iteration would be an asynchronous integration with standardized APIs like standard CVE databases or Vulners to provide reports against the actual ecosystem.

