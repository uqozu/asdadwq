
import os
import sys
import re
import json
import socket
import platform
import subprocess
import ipaddress
import getpass
import struct
import time

from datetime import datetime, timedelta
from urllib.parse import urlsplit

import requests
import psutil
import cpuinfo


# ==========================================
# CONFIGURATION
# ==========================================

TIMEOUT = 15

session = requests.Session()
session.trust_env = True  # Использовать настройки прокси


# ==========================================
# HELPERS
# ==========================================

def section(name):
    print("\n" + "=" * 65)
    print(f"  {name}")
    print("=" * 65)


def show(label, value):
    if value is None or value == "":
        value = "Unknown"

    print(f"{label:<27}: {value}")


def human_bytes(value):
    if value is None:
        return "Unknown"

    value = float(value)

    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if value < 1024:
            return f"{value:.2f} {unit}"
        value /= 1024

    return f"{value:.2f} EB"


def run_command(command, timeout=8):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace"
        )

        if result.returncode == 0:
            return result.stdout.strip()

    except Exception:
        pass

    return None


def uptime():
    seconds = int(time.time() - psutil.boot_time())
    return str(timedelta(seconds=seconds))


# ==========================================
# PROXY INFORMATION
# ==========================================

def get_proxy_info():
    section("PROXY CONFIGURATION")

    proxies = requests.utils.get_environ_proxies(
        "https://api.ipify.org"
    )

    if not proxies:
        show("Proxy", "Not detected in environment")
        return

    for protocol, address in proxies.items():
        try:
            parsed = urlsplit(
                address if "://" in address else "//" + address
            )

            host = parsed.hostname or "Unknown"
            port = parsed.port or "Default"

            # Не показываем логин и пароль прокси
            show(protocol.upper(), f"{parsed.scheme or 'proxy'}://{host}:{port}")

        except Exception:
            show(protocol.upper(), "Configured")


# ==========================================
# PUBLIC IP INFORMATION
# ==========================================

def get_public_ip(version):
    url = (
        "https://api4.ipify.org"
        if version == 4
        else "https://api6.ipify.org"
    )

    try:
        response = session.get(url, timeout=TIMEOUT)
        response.raise_for_status()

        ip = response.text.strip()

        if ipaddress.ip_address(ip).version != version:
            return None

        return ip

    except Exception:
        return None


def get_geo_info(ip):
    try:
        response = session.get(
            f"https://ipwho.is/{ip}",
            timeout=TIMEOUT
        )

        response.raise_for_status()
        data = response.json()

        if data.get("success"):
            return data

    except Exception as error:
        print(f"[!] GeoIP error: {error}")

    return None


def get_rdap_info(ip):
    try:
        response = session.get(
            f"https://rdap.org/ip/{ip}",
            timeout=TIMEOUT
        )

        response.raise_for_status()
        return response.json()

    except Exception:
        return None


def scan_public_ip(ip, version):
    section(f"PUBLIC IPv{version} INFORMATION")

    show("IP Address", ip)

    if not ip:
        show("Status", "Unavailable through current connection")
        return

    geo = get_geo_info(ip)

    if geo:
        section(f"IPv{version} GEOLOCATION")

        show("IP Type", geo.get("type"))
        show("Country", geo.get("country"))
        show("Country Code", geo.get("country_code"))
        show("Continent", geo.get("continent"))
        show("Continent Code", geo.get("continent_code"))
        show("Region", geo.get("region"))
        show("Region Code", geo.get("region_code"))
        show("City", geo.get("city"))
        show("Postal Code", geo.get("postal"))
        show("Capital", geo.get("capital"))
        show("EU Member", geo.get("is_eu"))

        show(
            "Coordinates",
            f"{geo.get('latitude')}, {geo.get('longitude')}"
        )

        # ISP / ASN
        connection = geo.get("connection") or {}

        section(f"IPv{version} NETWORK INFORMATION")

        show("ISP", connection.get("isp"))
        show("Organization", connection.get("org"))
        show("ASN", connection.get("asn"))
        show("Domain", connection.get("domain"))

        # Timezone
        timezone = geo.get("timezone") or {}

        section(f"IPv{version} TIMEZONE")

        show("Timezone", timezone.get("id"))
        show("Abbreviation", timezone.get("abbr"))
        show("UTC Offset", timezone.get("utc"))
        show("Local Time", timezone.get("current_time"))

        # Currency
        currency = geo.get("currency") or {}

        section(f"IPv{version} COUNTRY DETAILS")

        show("Currency", currency.get("name"))
        show("Currency Code", currency.get("code"))
        show("Currency Symbol", currency.get("symbol"))

        # Security flags, if provided by API
        security = geo.get("security") or {}

        if security:
            section(f"IPv{version} SECURITY FLAGS")

            for key, value in security.items():
                show(key.upper(), value)

    else:
        print("[!] GeoIP information unavailable.")

    # RDAP registration information
    rdap = get_rdap_info(ip)

    if rdap:
        section(f"IPv{version} RDAP / REGISTRATION")

        show("Object Type", rdap.get("objectClassName"))
        show("Handle", rdap.get("handle"))
        show("Network Name", rdap.get("name"))
        show("IP Version", rdap.get("ipVersion"))
        show("Start Address", rdap.get("startAddress"))
        show("End Address", rdap.get("endAddress"))
        show("Country", rdap.get("country"))
        show("Network Type", rdap.get("type"))
        show("Parent Handle", rdap.get("parentHandle"))

        for event in rdap.get("events", []):
            show(
                f"RDAP {event.get('eventAction')}",
                event.get("eventDate")
            )


# ==========================================
# OPERATING SYSTEM
# ==========================================

def scan_system():
    section("OPERATING SYSTEM INFORMATION")

    uname = platform.uname()

    show("Operating System", platform.system())
    show("OS Release", platform.release())
    show("OS Version", platform.version())
    show("Platform", platform.platform())
    show("Architecture", platform.machine())
    show("Processor Architecture", struct.calcsize("P") * 8)
    show("Hostname", socket.gethostname())
    show("FQDN", socket.getfqdn())
    show("Current Username", getpass.getuser())
    show("Python Version", platform.python_version())
    show("Python Executable", sys.executable)
    show("Boot Time", datetime.fromtimestamp(
        psutil.boot_time()
    ).strftime("%Y-%m-%d %H:%M:%S"))

    show("System Uptime", uptime())


# ==========================================
# MOTHERBOARD / COMPUTER MODEL
# ==========================================

def scan_hardware_model():
    section("COMPUTER / HARDWARE MODEL")

    system = platform.system()

    if system == "Windows":
        command = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_ComputerSystem | "
            "Select-Object -ExpandProperty Manufacturer; "
            "Get-CimInstance Win32_ComputerSystem | "
            "Select-Object -ExpandProperty Model"
        ]

        output = run_command(command)

        if output:
            lines = output.splitlines()
            show("Manufacturer", lines[0] if len(lines) > 0 else None)
            show("Computer Model", lines[1] if len(lines) > 1 else None)

        bios = run_command([
            "powershell",
            "-NoProfile",
            "-Command",
            "(Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion"
        ])

        show("BIOS Version", bios)

    elif system == "Linux":
        base = "/sys/class/dmi/id/"

        files = {
            "Manufacturer": "sys_vendor",
            "Computer Model": "product_name",
            "Board Manufacturer": "board_vendor",
            "Motherboard": "board_name",
            "BIOS Version": "bios_version",
            "BIOS Date": "bios_date"
        }

        for label, filename in files.items():
            try:
                with open(base + filename, "r", encoding="utf-8") as f:
                    show(label, f.read().strip())
            except Exception:
                show(label, None)

    elif system == "Darwin":
        output = run_command([
            "system_profiler", "SPHardwareDataType"
        ], timeout=15)

        if output:
            print(output)


# ==========================================
# CPU INFORMATION
# ==========================================

def scan_cpu():
    section("CPU INFORMATION")

    try:
        info = cpuinfo.get_cpu_info()

        show("CPU Model", info.get("brand_raw"))
        show("CPU Vendor", info.get("vendor_id_raw"))
        show("CPU Architecture", info.get("arch"))
        show("CPU Bits", info.get("bits"))
        show("Advertised Frequency", info.get("hz_advertised_friendly"))
        show("Actual Frequency", info.get("hz_actual_friendly"))

    except Exception as error:
        show("CPU Details", str(error))

    show("Physical Cores", psutil.cpu_count(logical=False))
    show("Logical Cores", psutil.cpu_count(logical=True))

    frequency = psutil.cpu_freq()

    if frequency:
        show("Current Frequency", f"{frequency.current:.0f} MHz")
        show("Minimum Frequency", f"{frequency.min:.0f} MHz")
        show("Maximum Frequency", f"{frequency.max:.0f} MHz")

    print("\nMeasuring CPU load...")

    usage = psutil.cpu_percent(interval=1, percpu=True)

    show("Total CPU Usage", f"{sum(usage)/len(usage):.1f}%")

    for index, value in enumerate(usage):
        show(f"Core {index} Usage", f"{value:.1f}%")

    if hasattr(os, "getloadavg"):
        try:
            show("Load Average", os.getloadavg())
        except Exception:
            pass


# ==========================================
# RAM INFORMATION
# ==========================================

def scan_ram():
    section("RAM INFORMATION")

    memory = psutil.virtual_memory()

    show("Total RAM", human_bytes(memory.total))
    show("Available RAM", human_bytes(memory.available))
    show("Used RAM", human_bytes(memory.used))
    show("RAM Usage", f"{memory.percent}%")

    swap = psutil.swap_memory()

    print("\n[ SWAP MEMORY ]")

    show("Total Swap", human_bytes(swap.total))
    show("Used Swap", human_bytes(swap.used))
    show("Free Swap", human_bytes(swap.free))
    show("Swap Usage", f"{swap.percent}%")


# ==========================================
# DISK INFORMATION
# ==========================================

def scan_disks():
    section("DISK INFORMATION")

    partitions = psutil.disk_partitions(all=False)

    for index, partition in enumerate(partitions):
        print(f"\n[ DISK / PARTITION {index + 1} ]")

        show("Device", partition.device)
        show("Mountpoint", partition.mountpoint)
        show("Filesystem", partition.fstype)

        try:
            usage = psutil.disk_usage(partition.mountpoint)

            show("Total Space", human_bytes(usage.total))
            show("Used Space", human_bytes(usage.used))
            show("Free Space", human_bytes(usage.free))
            show("Usage", f"{usage.percent}%")

        except Exception:
            show("Disk Usage", "Access denied / unavailable")


# ==========================================
# GPU INFORMATION
# ==========================================

def scan_gpu():
    section("GPU INFORMATION")

    # NVIDIA-specific details
    nvidia = run_command([
        "nvidia-smi",
        "--query-gpu=name,driver_version,memory.total,memory.used,temperature.gpu",
        "--format=csv,noheader"
    ])

    if nvidia:
        show("NVIDIA GPU", nvidia)

    system = platform.system()

    if system == "Windows":
        output = run_command([
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_VideoController | "
            "Select-Object -ExpandProperty Name"
        ])

    elif system == "Linux":
        output = run_command([
            "lspci"
        ])

        if output:
            output = "\n".join(
                line for line in output.splitlines()
                if re.search(r"VGA|3D controller|Display controller", line, re.I)
            )

    elif system == "Darwin":
        output = run_command([
            "system_profiler",
            "SPDisplaysDataType"
        ], timeout=15)

    else:
        output = None

    if output:
        show("Graphics Devices", output)
    else:
        show("Graphics Devices", "Not detected")


# ==========================================
# TEMPERATURE INFORMATION
# ==========================================

def scan_temperatures():
    section("HARDWARE TEMPERATURES")

    try:
        temperatures = psutil.sensors_temperatures()

        if not temperatures:
            show("Temperature Sensors", "Not available")
            return

        for name, entries in temperatures.items():
            for index, entry in enumerate(entries):
                label = entry.label or name

                show(
                    f"{label} #{index + 1}",
                    f"{entry.current} C"
                )

    except Exception:
        show("Temperature Sensors", "Not supported on this OS")


# ==========================================
# BATTERY
# ==========================================

def scan_battery():
    section("BATTERY INFORMATION")

    try:
        battery = psutil.sensors_battery()

        if battery is None:
            show("Battery", "Not detected")
            return

        show("Battery Percentage", f"{battery.percent}%")
        show("Power Plugged", battery.power_plugged)

        if battery.secsleft >= 0:
            show(
                "Remaining Time",
                str(timedelta(seconds=int(battery.secsleft)))
            )

    except Exception:
        show("Battery", "Information unavailable")


# ==========================================
# NETWORK INTERFACES
# ==========================================

def get_default_local_ip():
    # UDP connect determines the selected local route.
    # It does not send application data to the destination.
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("1.1.1.1", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return None


def scan_network():
    section("LOCAL NETWORK INFORMATION")

    show("Default Local IPv4", get_default_local_ip())

    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for name, addresses in interfaces.items():
        print(f"\n[ INTERFACE: {name} ]")

        status = stats.get(name)

        if status:
            show("Status", "UP" if status.isup else "DOWN")
            show("Speed", f"{status.speed} Mbps")
            show("MTU", status.mtu)
            show("Duplex", status.duplex)

        for address in addresses:
            if address.family == socket.AF_INET:
                show("IPv4", address.address)
                show("Netmask", address.netmask)
                show("Broadcast", address.broadcast)

            elif address.family == socket.AF_INET6:
                show("IPv6", address.address)

            elif address.family in (
                getattr(psutil, "AF_LINK", -999),
                getattr(socket, "AF_PACKET", -998)
            ):
                show("MAC Address", address.address)

    # Network traffic
    section("NETWORK TRAFFIC")

    counters = psutil.net_io_counters()

    show("Bytes Sent", human_bytes(counters.bytes_sent))
    show("Bytes Received", human_bytes(counters.bytes_recv))
    show("Packets Sent", counters.packets_sent)
    show("Packets Received", counters.packets_recv)
    show("Errors In", counters.errin)
    show("Errors Out", counters.errout)
    show("Dropped In", counters.dropin)
    show("Dropped Out", counters.dropout)


# ==========================================
# DNS INFORMATION
# ==========================================

def scan_dns():
    section("DNS INFORMATION")

    system = platform.system()
    servers = []

    if system == "Windows":
        output = run_command([
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-DnsClientServerAddress | "
            "ForEach-Object {$_.ServerAddresses}"
        ])

        if output:
            servers = output.splitlines()

    elif system == "Linux":
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8") as f:
                for line in f:
                    match = re.match(
                        r"\s*nameserver\s+(\S+)",
                        line
                    )
                    if match:
                        servers.append(match.group(1))
        except Exception:
            pass

    elif system == "Darwin":
        output = run_command(["scutil", "--dns"])

        if output:
            servers = re.findall(
                r"nameserver\[\d+\]\s*:\s*(\S+)",
                output
            )

    servers = list(dict.fromkeys(servers))

    if servers:
        for index, server in enumerate(servers):
            show(f"DNS Server {index + 1}", server)
    else:
        show("DNS Servers", "Not detected")


# ==========================================
# MAIN
# ==========================================

def main():
    print(r"""
 __  __ _   _ _____ ___ __  __ _____
|  \/  | | | |_   _|_ _|  \/  | ____|
| |\/| | | | | | |  | || |\/| |  _|
| |  | | |_| | | |  | || |  | | |___
|_|  |_|\___/  |_| |___|_|  |_|_____|

       ULTIMATE PC & IP SCANNER
""")

    print("Starting system scan...")
    print("This may take a little while.\n")

    get_proxy_info()

    # External IPv4 and IPv6
    print("\n[+] Checking public IP addresses...")

    ipv4 = get_public_ip(4)
    ipv6 = get_public_ip(6)

    print(f"[+] IPv4: {ipv4 or 'Unavailable'}")
    print(f"[+] IPv6: {ipv6 or 'Unavailable'}")

    # Public IP details
    if ipv4:
        scan_public_ip(ipv4, 4)

    if ipv6:
        scan_public_ip(ipv6, 6)

    # Local computer information
    scan_system()
    scan_hardware_model()
    scan_cpu()
    scan_ram()
    scan_disks()
    scan_gpu()
    scan_temperatures()
    scan_battery()
    scan_network()
    scan_dns()

    section("SCAN COMPLETED")

    show("Scan Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    show("IPv4 Detected", ipv4 or "No")
    show("IPv6 Detected", ipv6 or "No")
    show("System", platform.system())

    print("\nAll information collected locally.")
    print("Remember: IP addresses, username, hostname and MAC")
    print("addresses can be sensitive. Be careful sharing the report.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted.")
    except Exception as error:
        print(f"\n[!] Unexpected error: {error}")
