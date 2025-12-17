import sys
import os
import csv
import time
import webbrowser
import socket
import ipaddress
import threading
import subprocess
import xml.etree.ElementTree as ET
import ctypes
import shutil
from dataclasses import dataclass, field
from typing import Optional, Set, List, Dict, Tuple

import psutil
import requests
from ping3 import ping

from scapy.all import ARP, Ether, IGMP, conf, sniff, srp  # type: ignore

from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange  # type: ignore

from PySide6.QtCore import Qt, QThread, Signal, Slot, QTimer
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QComboBox, QTableWidget, QTableWidgetItem,
    QFileDialog, QCheckBox, QSpinBox, QMessageBox, QLineEdit, QGroupBox,
    QFormLayout
)


# -----------------------------
# Models
# -----------------------------
@dataclass
class Device:
    ip: str
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    rtt_ms: Optional[float] = None
    protocols: Set[str] = field(default_factory=set)
    description: Optional[str] = None
    last_seen_ts: float = field(default_factory=time.time)

    # extra raw hints
    mdns_names: Set[str] = field(default_factory=set)
    ssdp_server: Optional[str] = None
    ssdp_st: Optional[str] = None
    ssdp_usn: Optional[str] = None
    ssdp_location: Optional[str] = None
    open_tcp_ports: List[int] = field(default_factory=list)


# -----------------------------
# Utilities
# -----------------------------
def get_active_ipv4_interfaces() -> List[dict]:
    out = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for ifname, lst in addrs.items():
        st = stats.get(ifname)
        if not st or not st.isup:
            continue

        ipv4 = next((a for a in lst if a.family.name == "AF_INET"), None)
        if not ipv4 or not ipv4.address or not ipv4.netmask:
            continue

        ip = ipv4.address
        mask = ipv4.netmask
        try:
            net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        except Exception:
            continue

        out.append({
            "name": ifname,
            "ip": ip,
            "mask": mask,
            "network": str(net.network_address),
            "prefix": net.prefixlen,
            "cidr": str(net),
        })
    return out


DEFAULT_OUI_URL = "https://raw.githubusercontent.com/oui-lookup/ieee-oui/master/oui.csv"


def build_oui_map(path: str) -> Dict[str, str]:
    """
    CSV format: OUI,Vendor
    Example:
      FCFBFB,Apple, Inc.
      B827EB,Raspberry Pi Foundation
    """
    m: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split(",", 1)]
                if len(parts) != 2:
                    continue
                oui = parts[0].replace(":", "").replace("-", "").upper()
                if len(oui) >= 6:
                    m[oui[:6]] = parts[1]
    except FileNotFoundError:
        pass
    return m


def load_oui_map(path: str = "oui.csv", url: str = DEFAULT_OUI_URL) -> Dict[str, str]:
    """Ensure an OUI map is available by downloading a CSV if missing."""
    if not os.path.exists(path):
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200 and resp.text:
                with open(path, "w", encoding="utf-8", errors="ignore") as f:
                    f.write(resp.text)
        except Exception:
            pass

    return build_oui_map(path)


def vendor_from_mac(mac: Optional[str], oui_map: Dict[str, str]) -> Optional[str]:
    if not mac:
        return None
    key = mac.replace(":", "").replace("-", "").upper()[:6]
    return oui_map.get(key)


def safe_gethostbyaddr(ip: str) -> Optional[str]:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None


def ip_in_networks(ip: str, networks: List[ipaddress.IPv4Network]) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except Exception:
        return False
    for net in networks:
        if addr in net:
            return True
    return False


def parse_manual_range(text: str) -> List[ipaddress.IPv4Network]:
    text = text.strip()
    if not text:
        return []

    # CIDR
    if "/" in text:
        return [ipaddress.IPv4Network(text, strict=False)]

    # Start - End
    if "-" in text or "–" in text or "—" in text:
        normalized = text.replace("–", "-").replace("—", "-")
        parts = [p.strip() for p in normalized.split("-", 1)]
        if len(parts) != 2:
            raise ValueError("Invalid range format")
        start_ip = ipaddress.IPv4Address(parts[0])
        end_ip = ipaddress.IPv4Address(parts[1])
        if int(end_ip) < int(start_ip):
            raise ValueError("Start IP must be before End IP")
        return list(ipaddress.summarize_address_range(start_ip, end_ip))

    raise ValueError("Unsupported range format")


def normalize_description(existing: Optional[str], new: Optional[str]) -> Optional[str]:
    if not new:
        return existing
    if not existing:
        return new
    # avoid duplicates
    if new.lower() in existing.lower():
        return existing
    return f"{existing} | {new}"


def is_npcap_available() -> bool:
    try:
        sock = conf.L2socket()
        if sock:
            try:
                sock.close()
            except Exception:
                pass
            return True
        return False
    except Exception:
        return False


def parse_dhcp_info_from_ipconfig(interface_name: str) -> Dict[str, str]:
    try:
        output = subprocess.check_output(["ipconfig", "/all"], text=True, errors="ignore")
    except Exception:
        return {}

    lines = output.splitlines()
    capture = False
    info: Dict[str, str] = {}
    dns_collect = []
    i = 0
    target = interface_name.lower()
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped and not line.startswith(" "):
            capture = target in stripped.lower()
        elif capture and stripped:
            lower = stripped.lower()
            if lower.startswith("dhcp server"):
                info["dhcp_server"] = stripped.split(":", 1)[-1].strip()
            elif lower.startswith("lease obtained"):
                info["lease_start"] = stripped.split(":", 1)[-1].strip()
            elif lower.startswith("lease expires"):
                info["lease_end"] = stripped.split(":", 1)[-1].strip()
            elif lower.startswith("subnet mask"):
                info["subnet_mask"] = stripped.split(":", 1)[-1].strip()
            elif lower.startswith("default gateway"):
                parts = stripped.split(":", 1)
                if len(parts) > 1:
                    info["gateway"] = parts[1].strip()
                elif i + 1 < len(lines):
                    info["gateway"] = lines[i + 1].strip()
            elif lower.startswith("dns servers"):
                parts = stripped.split(":", 1)
                if len(parts) > 1 and parts[1].strip():
                    dns_collect.append(parts[1].strip())
                j = i + 1
                while j < len(lines) and lines[j].startswith("   "):
                    candidate = lines[j].strip()
                    if candidate:
                        dns_collect.append(candidate)
                    j += 1
            elif lower.startswith("ipv4 address") and "subnet" not in info:
                if "(" in stripped:
                    stripped = stripped.split("(", 1)[0]
                val = stripped.split(":", 1)[-1].strip()
                info["ip"] = val
        if capture and stripped and not line.startswith(" ") and target not in stripped.lower():
            break
        i += 1

    if dns_collect:
        info["dns"] = ", ".join(dns_collect)
    return info


def get_dhcp_info(interface_name: Optional[str], iface_data: Optional[dict]) -> Dict[str, str]:
    if not interface_name:
        return {}

    info = parse_dhcp_info_from_ipconfig(interface_name)
    if iface_data:
        info.setdefault("subnet_mask", iface_data.get("mask", ""))
    return info


# -----------------------------
# mDNS (Zeroconf) Collector
# -----------------------------
class MDNSCollector:
    """
    Browses a set of common service types and collects (ip -> names/services) mapping.
    Windows note: mDNS works only if devices advertise.
    """
    COMMON_TYPES = [
        "_workstation._tcp.local.",
        "_smb._tcp.local.",
        "_http._tcp.local.",
        "_https._tcp.local.",
        "_ssh._tcp.local.",
        "_rdlink._tcp.local.",
        "_airplay._tcp.local.",
        "_googlecast._tcp.local.",
        "_ipp._tcp.local.",
        "_printer._tcp.local.",
        "_raop._tcp.local.",  # AirTunes
    ]

    def __init__(self, duration_s: int = 5):
        self.duration_s = max(2, duration_s)
        self.zc = Zeroconf()
        self.lock = threading.Lock()
        self.ip_to_names: Dict[str, Set[str]] = {}
        self.ip_to_services: Dict[str, Set[str]] = {}

        self.browsers: List[ServiceBrowser] = []

    def _on_state_change(self, zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange):
        if state_change != ServiceStateChange.Added:
            return
        try:
            info = zeroconf.get_service_info(service_type, name, timeout=1500)
            if not info:
                return
            # Extract IPv4 addresses
            addrs = []
            for addr in info.addresses:
                if len(addr) == 4:
                    addrs.append(socket.inet_ntoa(addr))
            if not addrs:
                return

            # Human-ish label
            label = name
            server = getattr(info, "server", None)
            if server:
                label = server.rstrip(".")
            inst = name.split(".", 1)[0]
            pretty = label if label else inst

            with self.lock:
                for ip in addrs:
                    self.ip_to_names.setdefault(ip, set()).add(pretty)
                    self.ip_to_services.setdefault(ip, set()).add(service_type.replace(".local.", "").strip("."))

        except Exception:
            return

    def run(self) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
        try:
            for t in self.COMMON_TYPES:
                self.browsers.append(ServiceBrowser(self.zc, t, handlers=[self._on_state_change]))
            time.sleep(self.duration_s)
            with self.lock:
                return dict(self.ip_to_names), dict(self.ip_to_services)
        finally:
            try:
                self.zc.close()
            except Exception:
                pass


# -----------------------------
# SSDP / UPnP Discovery
# -----------------------------
def ssdp_discover(timeout_s: int = 3, mx: int = 2) -> Dict[str, dict]:
    """
    Returns mapping: ip -> ssdp_info
    ssdp_info includes headers (server, st, usn, location) for the "best" response.
    """
    timeout_s = max(1, timeout_s)
    mx = max(1, min(mx, 5))

    msearch = "\r\n".join([
        "M-SEARCH * HTTP/1.1",
        "HOST: 239.255.255.250:1900",
        'MAN: "ssdp:discover"',
        f"MX: {mx}",
        "ST: ssdp:all",
        "", ""
    ]).encode("utf-8")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(0.3)

    # Some stacks require TTL=2
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    except Exception:
        pass

    results: Dict[str, dict] = {}
    end = time.time() + timeout_s

    try:
        # send a couple of times for better coverage
        for _ in range(2):
            try:
                sock.sendto(msearch, ("239.255.255.250", 1900))
            except Exception:
                pass
            time.sleep(0.05)

        while time.time() < end:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception:
                break

            ip = addr[0]
            text = data.decode("utf-8", errors="ignore")
            if "HTTP/1.1" not in text.upper():
                continue

            headers = {}
            for line in text.split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            info = {
                "server": headers.get("server"),
                "st": headers.get("st"),
                "usn": headers.get("usn"),
                "location": headers.get("location"),
            }

            # keep first or prefer one with LOCATION
            if ip not in results:
                results[ip] = info
            else:
                if (not results[ip].get("location")) and info.get("location"):
                    results[ip] = info

    finally:
        try:
            sock.close()
        except Exception:
            pass

    return results


def fetch_upnp_friendly_name(location_url: str, timeout_s: float = 1.5) -> Optional[str]:
    """
    Fetch UPnP device description XML and extract friendlyName/modelName/manufacturer.
    Not all devices allow it or respond quickly.
    """
    if not location_url:
        return None
    try:
        r = requests.get(location_url, timeout=timeout_s, headers={"User-Agent": "LocalNetDiscovery/1.0"})
        if r.status_code != 200 or not r.text:
            return None
        # Parse XML
        root = ET.fromstring(r.text)
        # UPnP XML usually has namespaces; strip them
        def strip_ns(tag: str) -> str:
            return tag.split("}", 1)[-1] if "}" in tag else tag

        friendly = None
        model = None
        manuf = None

        for el in root.iter():
            t = strip_ns(el.tag)
            if t == "friendlyName" and el.text:
                friendly = el.text.strip()
            elif t == "modelName" and el.text:
                model = el.text.strip()
            elif t == "manufacturer" and el.text:
                manuf = el.text.strip()

        parts = [p for p in [friendly, model, manuf] if p]
        if not parts:
            return None
        # Keep it short-ish
        return " / ".join(parts[:3])
    except Exception:
        return None


# -----------------------------
# Worker
# -----------------------------
class ScanWorker(QThread):
    result = Signal(list)          # List[Device]
    status = Signal(str)
    finished_ok = Signal()

    def __init__(
        self,
        cidrs: List[ipaddress.IPv4Network],
        iface_name: Optional[str],
        do_ping: bool,
        do_mdns: bool,
        do_ssdp: bool,
        do_rdns: bool,
        fetch_upnp_xml: bool,
        mdns_duration_s: int,
        ssdp_timeout_s: int,
        parent=None
    ):
        super().__init__(parent)
        self.cidrs = cidrs
        self.iface_name = iface_name
        self.do_ping = do_ping
        self.do_mdns = do_mdns
        self.do_ssdp = do_ssdp
        self.do_rdns = do_rdns
        self.fetch_upnp_xml = fetch_upnp_xml
        self.mdns_duration_s = mdns_duration_s
        self.ssdp_timeout_s = ssdp_timeout_s
        self._stop = False

    def stop(self):
        self._stop = True

    def _merge_device(self, devices: Dict[str, Device], ip: str) -> Device:
        d = devices.get(ip)
        if not d:
            d = Device(ip=ip)
            devices[ip] = d
        d.last_seen_ts = time.time()
        return d

    def run(self):
        original_iface = conf.iface
        try:
            if self.iface_name:
                conf.iface = self.iface_name

            devices: Dict[str, Device] = {}

            npcap_available = is_npcap_available()

            # 1) ARP scan
            if npcap_available:
                for net in self.cidrs:
                    self.status.emit(f"Scanning {net} (ARP)...")
                    targets = [str(ip) for ip in net.hosts()]

                    conf.verb = 0
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets)

                    ans, _ = srp(pkt, timeout=2, retry=1)
                    for _, rcv in ans:
                        if self._stop:
                            self.status.emit("Scan stopped.")
                            return
                        ip = rcv.psrc
                        if not ip_in_networks(ip, self.cidrs):
                            continue
                        d = self._merge_device(devices, ip)
                        d.mac = rcv.hwsrc
                        d.protocols.add("ARP")
            else:
                self.status.emit("ARP disabled (Npcap not available).")

            # 2) SSDP / UPnP
            if self.do_ssdp and not self._stop:
                self.status.emit(f"Discovering UPnP/SSDP (timeout {self.ssdp_timeout_s}s)...")
                ssdp = ssdp_discover(timeout_s=self.ssdp_timeout_s, mx=2)
                for ip, info in ssdp.items():
                    if self._stop:
                        self.status.emit("Scan stopped.")
                        return
                    if not ip_in_networks(ip, self.cidrs):
                        continue
                    d = self._merge_device(devices, ip)
                    d.protocols.add("SSDP")
                    d.ssdp_server = info.get("server")
                    d.ssdp_st = info.get("st")
                    d.ssdp_usn = info.get("usn")
                    d.ssdp_location = info.get("location")

                    # Basic description from SSDP headers
                    desc_bits = []
                    if d.ssdp_st:
                        desc_bits.append(d.ssdp_st)
                    if d.ssdp_server:
                        desc_bits.append(d.ssdp_server)
                    if desc_bits:
                        d.description = normalize_description(d.description, "UPnP: " + " | ".join(desc_bits[:2]))

                # Optional: Fetch UPnP XML for friendlyName
                if self.fetch_upnp_xml and not self._stop:
                    self.status.emit("Fetching UPnP device descriptions (XML)...")
                    for ip, d in list(devices.items()):
                        if self._stop:
                            self.status.emit("Scan stopped.")
                            return
                        if not d.ssdp_location:
                            continue
                        pretty = fetch_upnp_friendly_name(d.ssdp_location, timeout_s=1.5)
                        if pretty:
                            d.description = normalize_description(d.description, pretty)

            # 3) mDNS / Bonjour
            if self.do_mdns and not self._stop:
                self.status.emit(f"Discovering mDNS/Bonjour (listening {self.mdns_duration_s}s)...")
                collector = MDNSCollector(duration_s=self.mdns_duration_s)
                ip_to_names, ip_to_services = collector.run()

                for ip, names in ip_to_names.items():
                    if self._stop:
                        self.status.emit("Scan stopped.")
                        return
                    if not ip_in_networks(ip, self.cidrs):
                        continue
                    d = self._merge_device(devices, ip)
                    d.protocols.add("mDNS")
                    for n in names:
                        d.mdns_names.add(n)
                    # Prefer hostname from mDNS if empty
                    if not d.hostname and d.mdns_names:
                        # pick a deterministic one
                        d.hostname = sorted(d.mdns_names)[0]

                    # Add services to description
                    svcs = ip_to_services.get(ip, set())
                    if svcs:
                        d.description = normalize_description(d.description, "mDNS: " + ",".join(sorted(svcs)[:6]))

            # 4) Ping RTT
            if self.do_ping and not self._stop:
                self.status.emit("Measuring latency (ICMP ping)...")
                # Ping known devices first; optional: you can ping all hosts but it's heavy
                for ip, d in list(devices.items()):
                    if self._stop:
                        self.status.emit("Scan stopped.")
                        return
                    try:
                        r = ping(ip, timeout=1.0, unit="ms")
                        if r is not None:
                            d.rtt_ms = float(r)
                            d.protocols.add("ICMP")
                    except Exception:
                        pass

            # 5) Reverse DNS
            if self.do_rdns and not self._stop:
                self.status.emit("Resolving hostnames (Reverse DNS)...")
                for ip, d in list(devices.items()):
                    if self._stop:
                        self.status.emit("Scan stopped.")
                        return
                    if d.hostname:
                        continue
                    name = safe_gethostbyaddr(ip)
                    if name:
                        d.hostname = name
                        d.protocols.add("rDNS")

            self.result.emit(list(devices.values()))
            self.finished_ok.emit()

        except PermissionError:
            self.status.emit("Error: Permission denied. Run as Administrator (and ensure Npcap installed).")
        except Exception as e:
            self.status.emit(f"Error: {e}")
        finally:
            conf.iface = original_iface


# -----------------------------
# GUI
# -----------------------------
class MainWindow(QMainWindow):
    externalIpChanged = Signal(str)
    internetStatusChanged = Signal(bool)
    igmpStatusChanged = Signal(dict)
    envStatusChanged = Signal(dict)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Local Network Device Discovery (Windows)")
        self.resize(1180, 680)

        self.oui_map = load_oui_map("oui.csv")
        self.worker: Optional[ScanWorker] = None
        self.devices: List[Device] = []
        self.npcap_available = False
        self.last_connectivity_state: Optional[bool] = None
        self.last_connectivity_ts: float = 0.0
        self.igmp_check_running = False
        self.env_check_running = False

        self.externalIpChanged.connect(self.set_external_ip)
        self.internetStatusChanged.connect(self.set_connectivity_state)
        self.igmpStatusChanged.connect(self.apply_igmp_status)
        self.envStatusChanged.connect(self.apply_env_status)

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)

        # Top controls
        top = QHBoxLayout()
        layout.addLayout(top)

        top.addWidget(QLabel("Interface:"))
        self.if_combo = QComboBox()
        top.addWidget(self.if_combo, 3)

        self.cb_ping = QCheckBox("Ping (ICMP)")
        self.cb_ping.setChecked(True)
        top.addWidget(self.cb_ping)

        self.cb_mdns = QCheckBox("mDNS / Bonjour")
        self.cb_mdns.setChecked(True)
        top.addWidget(self.cb_mdns)

        self.cb_ssdp = QCheckBox("UPnP / SSDP")
        self.cb_ssdp.setChecked(True)
        top.addWidget(self.cb_ssdp)

        self.cb_rdns = QCheckBox("Reverse DNS")
        self.cb_rdns.setChecked(False)
        top.addWidget(self.cb_rdns)

        self.cb_upnp_xml = QCheckBox("Fetch UPnP XML (friendlyName)")
        self.cb_upnp_xml.setChecked(False)
        top.addWidget(self.cb_upnp_xml)

        range_layout = QHBoxLayout()
        layout.addLayout(range_layout)
        range_layout.addWidget(QLabel("Custom range (optional):"))
        self.range_input = QLineEdit()
        self.range_input.setPlaceholderText("192.168.1.0/24 or 192.168.1.10-192.168.1.50")
        range_layout.addWidget(self.range_input)

        # Timing controls
        timing = QHBoxLayout()
        layout.addLayout(timing)

        timing.addWidget(QLabel("mDNS seconds:"))
        self.sp_mdns = QSpinBox()
        self.sp_mdns.setRange(2, 20)
        self.sp_mdns.setValue(5)
        timing.addWidget(self.sp_mdns)

        timing.addWidget(QLabel("SSDP timeout:"))
        self.sp_ssdp = QSpinBox()
        self.sp_ssdp.setRange(1, 10)
        self.sp_ssdp.setValue(3)
        timing.addWidget(self.sp_ssdp)

        timing.addStretch(1)

        self.btn_scan = QPushButton("Start Scan")
        self.btn_stop = QPushButton("Stop Scan")
        self.btn_export = QPushButton("Export CSV")
        self.btn_install_npcap = QPushButton("Install Npcap")
        self.btn_install_npcap.setVisible(False)
        self.btn_stop.setEnabled(False)
        timing.addWidget(self.btn_scan)
        timing.addWidget(self.btn_stop)
        timing.addWidget(self.btn_export)
        timing.addWidget(self.btn_install_npcap)

        network_group = QGroupBox("Network Info")
        layout.addWidget(network_group)
        network_form = QFormLayout()
        network_form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        network_form.setFormAlignment(Qt.AlignLeft | Qt.AlignTop)
        network_form.setHorizontalSpacing(12)
        network_form.setVerticalSpacing(4)
        network_group.setLayout(network_form)

        label_width = 160

        def make_label(text: str) -> QLabel:
            lbl = QLabel(text)
            lbl.setMinimumWidth(label_width)
            lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            return lbl

        header_row = QWidget()
        header_layout = QHBoxLayout(header_row)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(12)
        self.external_ip_lbl = QLabel("External IP: fetching...")
        header_layout.addWidget(self.external_ip_lbl)

        self.connectivity_lbl = QLabel("Internet: checking...")
        self.connectivity_lbl.setStyleSheet("color: red;")
        header_layout.addWidget(self.connectivity_lbl)
        header_layout.addStretch(1)

        network_form.addRow(make_label("External / Internet:"), header_row)

        dhcp_labels = [
            ("DHCP Server:", "dhcp_server"),
            ("Lease start:", "lease_start"),
            ("Lease expiration:", "lease_end"),
            ("Subnet mask:", "subnet_mask"),
            ("Default gateway:", "gateway"),
            ("DNS servers:", "dns"),
            ("Interface:", "interface"),
        ]

        self.dhcp_value_labels: Dict[str, QLabel] = {}
        for row, (title, key) in enumerate(dhcp_labels):
            label_widget = make_label(title)
            val_lbl = QLabel("")
            val_lbl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            self.dhcp_value_labels[key] = val_lbl
            network_form.addRow(label_widget, val_lbl)

        panels_row = QWidget()
        panels_layout = QHBoxLayout(panels_row)
        panels_layout.setContentsMargins(0, 0, 0, 0)
        panels_layout.setSpacing(12)

        self.igmp_group = QGroupBox("Multicast / IGMP")
        igmp_layout = QVBoxLayout(self.igmp_group)
        self.igmp_status_lbl = QLabel("IGMP Snooping: Unknown")
        self.igmp_status_lbl.setToolTip(
            "Best-effort inference; definitive snooping status requires switch/router access."
        )
        igmp_layout.addWidget(self.igmp_status_lbl)
        igmp_layout.addStretch(1)
        panels_layout.addWidget(self.igmp_group, 1)

        self.env_group = QGroupBox("Environment Status")
        env_layout = QVBoxLayout(self.env_group)
        self.npcap_status_lbl = QLabel("Npcap Installed: Unknown")
        env_layout.addWidget(self.npcap_status_lbl)
        self.admin_status_lbl = QLabel("Running as Administrator: Unknown")
        env_layout.addWidget(self.admin_status_lbl)
        self.arp_status_lbl = QLabel("ARP Available: Unknown")
        env_layout.addWidget(self.arp_status_lbl)
        arp_hint = QLabel("ARP may require Admin and/or Npcap for best results.")
        arp_hint.setStyleSheet("color: gray; font-size: 11px;")
        env_layout.addWidget(arp_hint)
        env_btn_row = QHBoxLayout()
        env_btn_row.addStretch(1)
        self.btn_env_refresh = QPushButton("Refresh")
        env_btn_row.addWidget(self.btn_env_refresh)
        env_layout.addLayout(env_btn_row)
        panels_layout.addWidget(self.env_group, 1)

        network_form.addRow(make_label("Status Panels:"), panels_row)

        vendor_status = (
            f"Ready. Loaded {len(self.oui_map)} OUI prefixes."
            if self.oui_map
            else "Ready. MAC vendor lookup unavailable (oui.csv not loaded)."
        )
        self.status_lbl = QLabel(vendor_status)
        layout.addWidget(self.status_lbl)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["IP", "MAC Address", "MAC Vendor", "Hostname", "Ping (ms)", "Protocols", "Description"]
        )
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)

        self.load_interfaces()

        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_export.clicked.connect(self.export_csv)
        self.btn_install_npcap.clicked.connect(self.open_npcap_download)
        self.if_combo.currentIndexChanged.connect(self.on_interface_changed)
        self.btn_env_refresh.clicked.connect(self.run_env_checks)

        self.update_npcap_state()
        self.fetch_external_ip()
        self.connectivity_check_running = False
        self.connectivity_timer = QTimer(self)
        self.connectivity_timer.setInterval(5000)
        self.connectivity_timer.timeout.connect(self.check_connectivity)
        self.connectivity_timer.start()
        self.igmp_timer = QTimer(self)
        self.igmp_timer.setInterval(20000)
        self.igmp_timer.timeout.connect(self.run_igmp_check)
        self.igmp_timer.start()
        self.env_timer = QTimer(self)
        self.env_timer.setInterval(20000)
        self.env_timer.timeout.connect(self.run_env_checks)
        self.env_timer.start()
        self.on_interface_changed(self.if_combo.currentIndex())

    def update_npcap_state(self):
        self.npcap_available = is_npcap_available()
        self.btn_install_npcap.setVisible(not self.npcap_available)
        if self.npcap_available:
            if self.status_lbl.text().startswith("Npcap is not installed"):
                self.status_lbl.setText("Ready.")
        else:
            self.status_lbl.setText("Npcap is not installed. ARP (MAC discovery) is disabled.")

    def open_npcap_download(self):
        webbrowser.open("https://npcap.com/#download")

    def fetch_external_ip(self):
        def worker():
            ip_text = "Unavailable"
            try:
                resp = requests.get("https://api.ipify.org", timeout=3)
                if resp.status_code == 200 and resp.text:
                    ip_text = resp.text.strip()
            except Exception:
                ip_text = "Unavailable"

            self.externalIpChanged.emit(ip_text or "Unavailable")

        threading.Thread(target=worker, daemon=True).start()

    @Slot(str)
    def set_external_ip(self, ip: str):
        self.external_ip_lbl.setText(f"External IP: {ip or 'Unavailable'}")

    @Slot(bool)
    def set_connectivity_state(self, online: bool):
        color = "green" if online else "red"
        text = "Online" if online else "Offline"
        self.connectivity_lbl.setText(f"Internet: {text}")
        self.connectivity_lbl.setStyleSheet(f"color: {color}; font-weight: bold;")
        self.connectivity_check_running = False

    def check_connectivity(self):
        if self.connectivity_check_running:
            return
        self.connectivity_check_running = True

        def worker():
            try:
                def socket_reachable(host: str, port: int, timeout: float) -> bool:
                    try:
                        with socket.create_connection((host, port), timeout=timeout):
                            return True
                    except Exception:
                        return False

                online = False

                for target in [("1.1.1.1", 443), ("8.8.8.8", 53)]:
                    if socket_reachable(target[0], target[1], 0.8):
                        online = True
                        break

                if not online:
                    for url in [
                        "https://www.msftconnecttest.com/connecttest.txt",
                        "https://www.google.com/generate_204",
                    ]:
                        try:
                            resp = requests.get(url, timeout=1.5, allow_redirects=False)
                            if resp.status_code in (200, 204):
                                online = True
                                break
                        except Exception:
                            continue

                now = time.time()
                should_emit = (
                    self.last_connectivity_state is None
                    or online != self.last_connectivity_state
                    or (now - self.last_connectivity_ts) > 15
                )

                if should_emit:
                    self.last_connectivity_state = online
                    self.last_connectivity_ts = now
                    self.internetStatusChanged.emit(online)
            finally:
                self.connectivity_check_running = False

        threading.Thread(target=worker, daemon=True).start()

    def _style_status(self, lbl: QLabel, prefix: str, status: str, color_map: Dict[str, str]):
        color = color_map.get(status.lower(), "black")
        lbl.setText(f"{prefix}: {status}")
        lbl.setStyleSheet(f"color: {color}; font-weight: bold;")

    def _contains_multicast_join(self, text: str) -> bool:
        for token in text.split():
            try:
                ip = ipaddress.IPv4Address(token.strip(','))
            except Exception:
                continue
            if ip.is_multicast:
                return True
        return False

    def _check_multicast_joins(self) -> Optional[bool]:
        commands = [
            ["netsh", "interface", "ip", "show", "joins"],
            ["netstat", "-g"],
        ]
        for cmd in commands:
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            except FileNotFoundError:
                continue
            except Exception:
                continue
            output = f"{proc.stdout}\n{proc.stderr}" if proc else ""
            if output and self._contains_multicast_join(output):
                return True
        if not any(shutil.which(cmd[0]) for cmd in commands):
            return None
        return False

    def _passive_igmp_sniff(self, iface_name: Optional[str]) -> Optional[bool]:
        if not iface_name:
            return None
        try:
            packets = sniff(filter="igmp", iface=iface_name, timeout=2, store=True, count=5)
            for pkt in packets:
                if pkt.haslayer(IGMP):
                    return True
            return False if packets else False
        except Exception:
            return None

    def detect_igmp_status(self, iface_name: Optional[str]) -> dict:
        status = "Unknown"
        detail = ""

        joins_present = self._check_multicast_joins()
        if joins_present:
            status = "Likely"
            detail = "Multicast group joins detected."
        else:
            sniff_result = self._passive_igmp_sniff(iface_name)
            if sniff_result:
                status = "Likely"
                detail = "Observed IGMP traffic."
        return {"status": status, "detail": detail}

    def run_igmp_check(self):
        if self.igmp_check_running:
            return
        self.igmp_check_running = True
        data = self.if_combo.currentData()
        iface_name = data.get("name") if isinstance(data, dict) else None

        def worker():
            try:
                result = self.detect_igmp_status(iface_name)
            except Exception:
                result = {"status": "Unknown", "detail": ""}
            self.igmpStatusChanged.emit(result)

        threading.Thread(target=worker, daemon=True).start()

    @Slot(dict)
    def apply_igmp_status(self, payload: dict):
        try:
            status = str(payload.get("status", "Unknown"))
            detail = payload.get("detail") or ""
            tooltip = "Best-effort inference; definitive snooping status requires switch/router access."
            if detail:
                tooltip = f"{tooltip} {detail}"
            self.igmp_status_lbl.setToolTip(tooltip)
            color_map = {"likely": "green", "unknown": "orange", "unlikely": "red"}
            self._style_status(self.igmp_status_lbl, "IGMP Snooping", status, color_map)
        finally:
            self.igmp_check_running = False

    def _check_npcap_installed(self) -> Optional[bool]:
        try:
            proc = subprocess.run(["sc", "query", "npcap"], capture_output=True, text=True, timeout=3)
            if proc.returncode == 0 and proc.stdout:
                return True
        except FileNotFoundError:
            pass
        except Exception:
            return None

        system_root = os.environ.get("SystemRoot", "C:\\Windows")
        for dll in ["wpcap.dll", "Packet.dll"]:
            dll_path = os.path.join(system_root, "System32", dll)
            if os.path.exists(dll_path):
                return True
        return False

    def _check_is_admin(self) -> Optional[bool]:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return None

    def _check_arp_available(self) -> Optional[bool]:
        try:
            proc = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=3)
        except FileNotFoundError:
            return None
        except Exception:
            return None

        output = (proc.stdout or "") + (proc.stderr or "")
        lower = output.lower()
        if "denied" in lower or "permission" in lower:
            return False
        return proc.returncode == 0

    def detect_env_status(self) -> dict:
        npcap_state = self._check_npcap_installed()
        admin_state = self._check_is_admin()
        arp_state = self._check_arp_available()

        def to_text(val: Optional[bool], true_text: str, false_text: str) -> str:
            if val is True:
                return true_text
            if val is False:
                return false_text
            return "Unknown"

        return {
            "npcap": to_text(npcap_state, "Installed", "Not installed"),
            "admin": to_text(admin_state, "Admin", "Not Admin"),
            "arp": to_text(arp_state, "Available", "Limited/Unavailable"),
        }

    def run_env_checks(self):
        if self.env_check_running:
            return
        self.env_check_running = True

        def worker():
            try:
                result = self.detect_env_status()
            except Exception:
                result = {"npcap": "Unknown", "admin": "Unknown", "arp": "Unknown"}
            self.envStatusChanged.emit(result)

        threading.Thread(target=worker, daemon=True).start()

    @Slot(dict)
    def apply_env_status(self, payload: dict):
        try:
            color_map_basic = {"installed": "green", "not installed": "red", "unknown": "orange"}
            color_map_admin = {"admin": "green", "not admin": "red", "unknown": "orange"}
            color_map_arp = {
                "available": "green",
                "limited/unavailable": "red",
                "unknown": "orange",
            }
            self._style_status(self.npcap_status_lbl, "Npcap Installed", payload.get("npcap", "Unknown"), color_map_basic)
            self._style_status(self.admin_status_lbl, "Running as Administrator", payload.get("admin", "Unknown"), color_map_admin)
            self._style_status(self.arp_status_lbl, "ARP Available", payload.get("arp", "Unknown"), color_map_arp)
        finally:
            self.env_check_running = False

    def on_interface_changed(self, index: int):
        data = self.if_combo.itemData(index)
        iface_name = data.get("name") if isinstance(data, dict) else None
        info = get_dhcp_info(iface_name, data if isinstance(data, dict) else None)
        info["interface"] = iface_name or "N/A"
        for key, lbl in self.dhcp_value_labels.items():
            lbl.setText(info.get(key, "") or "N/A")
        self.run_igmp_check()
        self.run_env_checks()


    def load_interfaces(self):
        self.if_combo.clear()
        ifaces = get_active_ipv4_interfaces()
        if not ifaces:
            self.if_combo.addItem("No active IPv4 interfaces found", None)
            self.btn_scan.setEnabled(False)
            return
        for it in ifaces:
            label = f"{it['name']}  |  {it['ip']}  |  {it['cidr']}"
            self.if_combo.addItem(label, it)

    def start_scan(self):
        self.update_npcap_state()
        it = self.if_combo.currentData()
        if not it:
            return

        if not self.npcap_available:
            QMessageBox.information(
                self,
                "Npcap not installed",
                "Npcap is not installed. MAC/Vendor discovery (ARP) is disabled until you install Npcap. Use the Install Npcap button to download it.",
            )

        # quick warning: UPnP XML fetch can slow down
        if self.cb_upnp_xml.isChecked() and not self.cb_ssdp.isChecked():
            QMessageBox.information(self, "Note", "UPnP XML requires SSDP enabled.")

        cidrs: List[ipaddress.IPv4Network] = []
        range_text = self.range_input.text().strip()
        if range_text:
            try:
                cidrs = parse_manual_range(range_text)
            except Exception as e:
                QMessageBox.warning(self, "Invalid range", f"Please enter a valid CIDR or IP range. ({e})")
                self.btn_scan.setEnabled(True)
                return
        else:
            cidrs = [ipaddress.IPv4Network(it["cidr"], strict=False)]

        cidr_label = ", ".join(str(n) for n in cidrs)

        self.table.setRowCount(0)
        self.devices = []
        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.status_lbl.setText(f"Starting scan on {cidr_label} ...")

        self.worker = ScanWorker(
            cidrs=cidrs,
            iface_name=it["name"],
            do_ping=self.cb_ping.isChecked(),
            do_mdns=self.cb_mdns.isChecked(),
            do_ssdp=self.cb_ssdp.isChecked(),
            do_rdns=self.cb_rdns.isChecked(),
            fetch_upnp_xml=(self.cb_ssdp.isChecked() and self.cb_upnp_xml.isChecked()),
            mdns_duration_s=int(self.sp_mdns.value()),
            ssdp_timeout_s=int(self.sp_ssdp.value()),
        )
        self.worker.status.connect(self.status_lbl.setText)
        self.worker.result.connect(self.on_results)
        self.worker.finished_ok.connect(self.on_finished)
        self.worker.start()

    def stop_scan(self):
        if self.worker:
            self.worker.stop()
        self.btn_stop.setEnabled(False)
        self.btn_scan.setEnabled(True)

    def on_finished(self):
        self.btn_stop.setEnabled(False)
        self.btn_scan.setEnabled(True)
        self.status_lbl.setText(f"Done. Found {len(self.devices)} devices.")

    def on_results(self, devices: list):
        self.devices = devices

        # enrich vendor
        for d in self.devices:
            d.vendor = vendor_from_mac(d.mac, self.oui_map)

        # Stable order: by IP
        try:
            self.devices.sort(key=lambda x: ipaddress.IPv4Address(x.ip))
        except Exception:
            pass

        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.devices))

        for row, d in enumerate(self.devices):
            self.table.setItem(row, 0, QTableWidgetItem(d.ip))
            self.table.setItem(row, 1, QTableWidgetItem(d.mac or ""))
            self.table.setItem(row, 2, QTableWidgetItem(d.vendor or ""))
            self.table.setItem(row, 3, QTableWidgetItem(d.hostname or ""))
            self.table.setItem(row, 4, QTableWidgetItem("" if d.rtt_ms is None else f"{d.rtt_ms:.2f}"))
            self.table.setItem(row, 5, QTableWidgetItem("|".join(sorted(d.protocols))))
            self.table.setItem(row, 6, QTableWidgetItem(d.description or ""))

            for col in range(7):
                item = self.table.item(row, col)
                item.setFlags(item.flags() ^ Qt.ItemIsEditable)

        self.table.setSortingEnabled(True)

    def export_csv(self):
        if not self.devices:
            self.status_lbl.setText("Nothing to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "devices.csv", "CSV Files (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["IP", "MAC", "Vendor", "Hostname", "Ping_ms", "Protocols", "Description"])
            for d in self.devices:
                w.writerow([
                    d.ip,
                    d.mac or "",
                    d.vendor or "",
                    d.hostname or "",
                    "" if d.rtt_ms is None else f"{d.rtt_ms:.2f}",
                    "|".join(sorted(d.protocols)),
                    d.description or ""
                ])
        self.status_lbl.setText(f"Exported: {path}")


def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
