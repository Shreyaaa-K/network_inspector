# Net Inspector

Net Inspector is a local, offline network inspection tool designed for network engineers to identify which servers an application is communicating with.

## Features (Phase 1)

- Detect active network connections per process
- Show destination IP and port
- Resolve FQDN when available
- Classify Private vs Public IP
- Works offline
- macOS and Linux support

## Requirements

Python 3.x

Install dependency:

pip install psutil

## Run

sudo python net_inspector.py

Output saved to:

net_inspector_output.txt

## Roadmap

Phase 2:
- Automatic process detection
- VPN interface detection
- Connection analysis

Phase 3:
- Standalone binary