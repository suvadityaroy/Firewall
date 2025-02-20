# Firewall (Python) — Features, Tech Stack, How It Works, and Proofs

![Last Commit](https://img.shields.io/github/last-commit/suvadityaroy/Firewall?style=for-the-badge)
![Latest Tag](https://img.shields.io/github/v/tag/suvadityaroy/Firewall?sort=semver&style=for-the-badge)
![Repo Size](https://img.shields.io/github/repo-size/suvadityaroy/Firewall?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge)

This project implements a simple, rules-driven software firewall in Python. It parses captured TCP/UDP packets, determines direction (inbound/outbound) via MAC address, and applies policy from INI configuration to accept, decline, or reject traffic.

## Features

- Packet parsing: Reads hex-formatted fields from captured packet logs ([packets/tcp.txt](packets/tcp.txt), [packets/udp.txt](packets/udp.txt)).
- Protocol detection: Uses the 23rd byte to identify TCP (`06`) vs UDP (`11`).
- Direction detection: Compares packet MAC to local MAC to classify packets as outbound or inbound.
- Rule engine: INI-based policies for `Accept`, `Decline`, `Reject` per IP and port for inbound and outbound traffic.
- Verbose tracing: Prints per-packet decisions for source/destination endpoints and overall transmission success/failure.

## Tech Stack

- Language: Python 3 (tested on Windows)
- Libraries: Python Standard Library (`configparser`, `os`, `sys`)
- Data: Packet captures saved to text files in `packets/` (prepared with Wireshark)

## Project Structure

```
main.py                 # Entrypoint: runs the demo on packets/tcp.txt
src/
  core.py               # Parsing loop, direction, and rule application
  rule_engine.py        # INI-driven rule checks for inbound/outbound
  util.py               # Helpers: hex→IP, hex→port, MAC comparison
  tcp_packet.py         # TCP packet model
  udp_packet.py         # UDP packet model
  inbound rules.ini     # Inbound policy
  outbound rules.ini    # Outbound policy
packets/
  tcp.txt               # Sample TCP capture (hex-separated fields)
  udp.txt               # Sample UDP capture
images/                 # Screens and diagrams referenced below
README.md               # This document
setup.py                # Packaging scaffold
```

## How It Works

1. Capture traffic with Wireshark and export key fields to text (see `packets/`).
2. Parse lines into an array of hex bytes in `src/core.py`:
	- Byte 23 → protocol (`06` = TCP, `11` = UDP).
	- Bytes 26–29 → source IP; 30–33 → destination IP.
	- Bytes 34–35 → source port; 36–37 → destination port.
3. Determine direction with `src/util.py:isSrc()` by comparing the packet MAC with the local MAC:
	- Match → packet is outbound (apply `outbound rules.ini`).
	- No match → packet is inbound (apply `inbound rules.ini`).
4. Evaluate policy in `src/rule_engine.py`:
	- Looks up IP in `Accepting ip`, `Declining ip`, `Rejecting ip` sections.
	- Ports are comma-separated per IP. Returns one of `Accept | Decline | Reject | No rule associated`.
5. A transmission succeeds only if both source and destination endpoints return `Accept` under the applicable direction.

## Setup (Windows)

Requirements:

- Python 3.8+ installed and available in PATH
- PowerShell (default on Windows)

Optional: create a virtual environment.

```powershell
cd d:\project\Firewall
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

## Run the Demo

From the project root:

```powershell
cd d:\project\Firewall
python main.py
```

Notes:

- The current `main.py` runs the TCP demo (`packets/tcp.txt`). You can adapt it to process UDP by passing the UDP file handle into `core.main()` similarly.
- If you see many “No rule associated” messages, add IP/port entries to the INI files.

## Configuration

- Inbound policy: [src/inbound rules.ini](src/inbound%20rules.ini)
- Outbound policy: [src/outbound rules.ini](src/outbound%20rules.ini)

Sections:

- `Accepting ip`: Allowed ports for each IP
- `Declining ip`: Explicitly declined ports for each IP
- `Rejecting ip`: Explicitly rejected ports for each IP

Example (outbound):

```ini
[Accepting ip]
192.168.1.6 = 63449,55173

[Declining ip]
192.168.1.6 = 63325,57762

[Rejecting ip]
192.168.1.6 = 63439,59051,63450
```

## Proofs

Screenshots (from `images/`):

- Protocol detection via byte 23: ![TCP vs UDP](images/check%20for%20TCP%20and%20UDP.PNG)
- Direction by MAC address: ![Inbound vs Outbound](images/check%20for%20MAC.PNG)
- Wireshark capture sample: ![Wireshark](images/tcp_wireshark.PNG)
- Capture text sample: ![txt](images/tcp_notepad.PNG)
- Flow overview: ![Explanation](images/explanation.png)

Sample console output (real run):

```
TCP packet: Src_ip:74.125.68.188 Dst_ip:192.168.1.6 Src_port:443 Dst_port:63323
packet comes to our server..
source ip:74.125.68.188 and port:443 will No rule associated!!!! Please assign a rule
Destination ip:192.168.1.6 and port:63323 will No rule associated!!!! Please assign a rule
Packet transmission unsuccessfull!!! Packet Dropped

TCP packet: Src_ip:192.168.1.6 Dst_ip:117.18.232.240 Src_port:63459 Dst_port:80
packet going out of our server..
source ip:192.168.1.6 and port:63459 will No rule associated!!!! Please assign a rule
Destination ip:117.18.232.240 and port:80 will No rule associated!!!! Please assign a rule
Packet transmission unsuccessfull!!! Packet Dropped
```

These outputs reflect the rule engine decisions given the current INI configuration. Adding the relevant IP/port entries under `Accepting ip` will change decisions to `Accept` and result in successful transmission messages.

## Customization & Extensibility

- Update `inbound rules.ini` and `outbound rules.ini` to reflect your environment.
- Modify `src/core.py` to adjust parsing if your capture format differs.
- Extend `tcp_packet.py` / `udp_packet.py` with additional headers if needed.

## Known Limitations

- Packet text format must match the expected positions; malformed lines may cause parsing errors (e.g., `IndexError`). Trim or standardize your captures if needed.
- The demo currently reads `packets/tcp.txt` in `main.py`. UDP handling is implemented in `src` but not wired in the demo entry.
