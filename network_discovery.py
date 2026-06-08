#!/usr/bin/env python3

import socket
import subprocess
import threading
import json
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor


def ping_host(ip):
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None


def get_mac(ip):
    try:
        result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True)
        for line in result.stdout.strip().split("\n"):
            for part in line.split():
                if ":" in part and len(part) == 17:
                    return part
    except Exception:
        pass
    return None


def guess_device_type(hostname, ip):
    if not hostname:
        return "Router/Gateway" if ip.endswith(".1") else "Unknown Device"

    h = hostname.lower()
    if any(x in h for x in ["router", "gateway", "fritz", "dlink", "tplink", "asus", "netgear"]):
        return "Router/Gateway"
    elif any(x in h for x in ["iphone", "ipad"]):
        return "Apple iPhone/iPad"
    elif any(x in h for x in ["macbook", "imac", "mac-mini", "apple"]):
        return "Apple Mac"
    elif any(x in h for x in ["android", "samsung", "pixel", "xiaomi"]):
        return "Android Device"
    elif any(x in h for x in ["windows", "desktop", "laptop"]):
        return "Windows PC"
    elif any(x in h for x in ["raspberrypi", "raspberry"]):
        return "Raspberry Pi"
    elif any(x in h for x in ["tv", "roku", "firetv", "appletv"]):
        return "Smart TV/Streaming"
    elif any(x in h for x in ["printer", "hp", "canon", "epson"]):
        return "Printer"
    else:
        return "Unknown Device"


def scan_host(ip, lock, results):
    if ping_host(ip):
        hostname = resolve_hostname(ip)
        mac = get_mac(ip)
        device_type = guess_device_type(hostname, ip)

        result = {
            "ip": ip,
            "hostname": hostname or "N/A",
            "mac": mac or "N/A",
            "device_type": device_type
        }

        with lock:
            results.append(result)
            hostname_str = f" ({hostname})" if hostname else ""
            print(f"  [+] {ip:<18}{hostname_str:<35} {device_type}")


def get_ip_range(base):
    return [f"{base}.{i}" for i in range(1, 255)]


def get_local_network():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        base = ".".join(local_ip.split(".")[:3])
        return local_ip, base
    except Exception:
        return None, None


def export_results(results, fmt="txt"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"network_discovery_{timestamp}.{fmt}"

    if fmt == "json":
        with open(filename, "w") as f:
            json.dump({"scan_time": timestamp, "devices_found": len(results), "devices": results}, f, indent=4)
    elif fmt == "txt":
        with open(filename, "w") as f:
            f.write(f"NetDiscover Report\nScan Time: {timestamp}\nDevices: {len(results)}\n{'='*70}\n")
            for r in results:
                f.write(f"  {r['ip']:<18} {r['hostname']:<35} {r['device_type']}\n")

    print(f"\n  [✓] Results saved to: {filename}")


def run_discovery(base, threads=50):
    ip_range = get_ip_range(base)
    results = []
    lock = threading.Lock()

    print(f"\n  Scanning {base}.0/24 — {len(ip_range)} hosts | {threads} threads\n")
    print(f"  {'IP':<18} {'Hostname':<35} {'Device Type'}")
    print(f"  {'─'*18} {'─'*35} {'─'*20}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for ip in ip_range:
            executor.submit(scan_host, ip, lock, results)

    return sorted(results, key=lambda x: int(x["ip"].split(".")[-1]))


if __name__ == "__main__":
    print("""
  NetDiscover — Local Network Device Scanner
  For authorized use only
    """)

    local_ip, base = get_local_network()

    if local_ip:
        print(f"  [i] Your IP  : {local_ip}")
        print(f"  [i] Network  : {base}.0/24")

    custom = input(f"\n  Network to scan [{base}]: ").strip()
    if custom:
        base = custom

    export = input("  Export? [txt/json/no, default txt]: ").strip().lower() or "txt"

    start_time = datetime.now()
    results = run_discovery(base)
    elapsed = (datetime.now() - start_time).total_seconds()

    print(f"\n  Discovery complete: {len(results)} device(s) found")
    print(f"  Time elapsed      : {elapsed:.2f}s")

    if export in ("txt", "json"):
        export_results(results, fmt=export)
