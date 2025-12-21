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
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, Set, List, Dict, Tuple

import psutil
from collections import defaultdict
import requests
from ping3 import ping

try:
    from scapy.all import ARP, Ether, Dot1Q, conf, sniff, srp, get_if_list  # type: ignore
    from scapy.layers.dns import DNS  # type: ignore
    from scapy.layers.inet import IP, UDP  # type: ignore
    from scapy.arch.windows import get_windows_if_list  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency at runtime
    ARP = Ether = conf = sniff = srp = IP = UDP = DNS = Dot1Q = get_if_list = None  # type: ignore
    get_windows_if_list = None  # type: ignore
    SCAPY_AVAILABLE = False

from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange  # type: ignore

from PySide6.QtCore import Qt, QThread, Signal, Slot, QTimer
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QComboBox, QTableWidget, QTableWidgetItem,
    QFileDialog, QCheckBox, QSpinBox, QMessageBox, QLineEdit, QGroupBox,
    QFormLayout, QTabWidget, QPlainTextEdit, QGridLayout, QScrollArea,
    QSplitter, QDoubleSpinBox
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
    sources: Set[str] = field(default_factory=set)
    description: Optional[str] = None
    last_seen_ts: float = field(default_factory=time.time)

    # extra raw hints
    mdns_names: Set[str] = field(default_factory=set)
    ssdp_server: Optional[str] = None
    ssdp_st: Optional[str] = None
    ssdp_usn: Optional[str] = None
    ssdp_location: Optional[str] = None
    open_tcp_ports: List[int] = field(default_factory=list)
    primary_key: Optional[str] = None
    ips_seen: Set[str] = field(default_factory=set)


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


def is_valid_mac(mac: Optional[str]) -> bool:
    if not mac:
        return False
    norm = mac.replace("-", ":").lower()
    if norm in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
        return False
    return bool(re.fullmatch(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", norm))


def is_device_online(d: Device) -> bool:
    if d.rtt_ms is not None:
        return True
    if d.protocols and any(p in d.protocols for p in ("ARP", "ICMP", "TCP")):
        return True
    if d.sources and any(s in d.sources for s in ("ARP", "ICMP", "TCP")):
        return True
    if d.mac and is_valid_mac(d.mac):
        return True
    return False


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


def parse_arp_table() -> Dict[str, str]:
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, errors="ignore")
    except Exception:
        return {}

    entries: Dict[str, str] = {}
    for line in output.splitlines():
        match = re.search(r"((?:\d{1,3}\.){3}\d{1,3})\s+([0-9a-fA-F:-]{12,17})", line)
        if not match:
            continue
        ip = match.group(1)
        mac = match.group(2).replace("-", ":").lower()
        if is_valid_mac(mac):
            entries[ip] = mac
    return entries


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
    if not SCAPY_AVAILABLE or conf is None:
        return False
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
# Passive Layer 2 / AV helpers
# -----------------------------
def parse_lldp_tlvs(raw: bytes) -> Dict[str, str]:
    info: Dict[str, str] = {}
    idx = 0
    length = len(raw)
    while idx + 2 <= length:
        t = (raw[idx] >> 1) & 0x7F
        l = ((raw[idx] & 0x01) << 8) | raw[idx + 1]
        idx += 2
        if l <= 0 or idx + l > length:
            break
        val = raw[idx:idx + l]
        idx += l
        if t == 0:  # End of LLDPDU
            break
        if t == 1 and l >= 2:  # Chassis ID
            info["chassis_id"] = val[1:].decode("utf-8", errors="ignore")
        elif t == 2 and l >= 2:  # Port ID
            info["port_id"] = val[1:].decode("utf-8", errors="ignore")
        elif t == 4:  # Port description
            info["port_description"] = val.decode("utf-8", errors="ignore")
        elif t == 5:  # System name
            info["system_name"] = val.decode("utf-8", errors="ignore")
        elif t == 8 and l >= 1:  # Management address
            info["management_address"] = val[1:].decode("utf-8", errors="ignore")
    return info


def resolve_capture_interface(target_name: Optional[str]) -> Optional[str]:
    if not target_name or not SCAPY_AVAILABLE:
        return target_name

    target_lower = target_name.lower()
    best_iface: Optional[str] = None
    best_score = 0

    def score(candidate: str) -> int:
        cand_lower = candidate.lower()
        if target_lower == cand_lower:
            return 5
        if target_lower in cand_lower:
            return 4
        if cand_lower in target_lower:
            return 3
        return 0

    try:
        if get_windows_if_list:
            for iface in get_windows_if_list():
                for key in ["friendlyname", "name", "description", "guid"]:
                    val = iface.get(key) if isinstance(iface, dict) else None
                    if not val:
                        continue
                    sc = score(str(val))
                    if sc > best_score:
                        best_score = sc
                        best_iface = iface.get("name") or iface.get("guid") or str(val)
    except Exception:
        pass

    try:
        if get_if_list:
            for iface in get_if_list():
                sc = score(iface)
                if sc > best_score:
                    best_score = sc
                    best_iface = iface
    except Exception:
        pass

    return best_iface or target_name


def summarize_multicast_evidence(packets: List) -> Tuple[Dict[str, str], List[str]]:
    summary: Dict[str, str] = {
        "multicast": "Unknown",
        "igmp": "Unknown",
        "igmp_querier": "Unknown",
        "ptp": "Unknown",
        "dante": "Unknown",
        "nvx": "Unknown",
    }
    evidence: List[str] = []

    if not packets:
        for k in summary:
            summary[k] = "Not detected"
        return summary, evidence

    multicast_count = 0
    igmp_seen = False
    ptp_seen = False
    dante_hint = False
    nvx_possible = False
    multicast_streams: Dict[str, int] = {}
    ptp_count = 0

    for pkt in packets:
        try:
            eth = pkt.getlayer(Ether)
            ip = pkt.getlayer(IP) if IP else None
            udp = pkt.getlayer(UDP) if UDP else None

            if eth:
                dst = getattr(eth, "dst", "")
                if dst.lower().startswith("01:00:5e"):
                    multicast_count += 1
                if getattr(eth, "type", None) == 0x88F7:
                    ptp_seen = True
                    ptp_count += 1

            if ip:
                dst_ip = getattr(ip, "dst", "")
                try:
                    if dst_ip and ipaddress.IPv4Address(dst_ip).is_multicast:
                        multicast_count += 1
                        if udp:
                            key = f"{dst_ip}:{getattr(udp, 'dport', '')}"
                            multicast_streams[key] = multicast_streams.get(key, 0) + 1
                except Exception:
                    pass
                if getattr(ip, "proto", None) == 2:
                    igmp_seen = True

            if udp:
                dport = getattr(udp, "dport", None)
                if dport in (319, 320):
                    ptp_seen = True
                    ptp_count += 1
                if dport == 5353 and DNS and pkt.haslayer(DNS):
                    dns_layer = pkt.getlayer(DNS)
                    qname = getattr(getattr(dns_layer, "qd", None), "qname", b"") or b""
                    if any(token in qname.lower() for token in [b"_dante._udp", b"_netaudio-arc._udp"]):
                        dante_hint = True
                if ip and dport and ipaddress.IPv4Address(getattr(ip, "dst", "0.0.0.0")).is_multicast:
                    if multicast_streams.get(f"{ip.dst}:{dport}", 0) > 5:
                        nvx_possible = True
        except Exception:
            continue

    if multicast_count > 0:
        summary["multicast"] = "Present"
        evidence.append(f"Observed multicast frames: {multicast_count}")
    else:
        summary["multicast"] = "None"

    if igmp_seen:
        summary["igmp"] = "Seen"
    else:
        summary["igmp"] = "Not seen"

    if igmp_seen:
        summary["igmp_querier"] = "Likely"
    else:
        summary["igmp_querier"] = "Not detected"

    if ptp_seen:
        summary["ptp"] = "Seen"
        evidence.append(f"Observed PTP packets count: {ptp_count}")
    else:
        summary["ptp"] = "Not seen"

    if dante_hint:
        summary["dante"] = "Likely"
        evidence.append("Observed mDNS service suggesting Dante (_dante._udp/_netaudio-arc._udp)")
    else:
        summary["dante"] = "Not detected"

    if nvx_possible:
        summary["nvx"] = "Possible"
        evidence.append("Detected sustained multicast UDP flows (possible AV/video)")
    else:
        summary["nvx"] = "Not detected"

    if multicast_streams:
        top_keys = list(multicast_streams.items())[:5]
        formatted = ", ".join(f"{k} (count {v})" for k, v in top_keys)
        evidence.append(f"Observed UDP multicast streams: {formatted}")

    return summary, evidence


# -----------------------------
# Worker
# -----------------------------
class ScanWorker(QThread):
    result = Signal(list)          # List[Device]
    status = Signal(str)
    finished_ok = Signal()
    batch_update = Signal(list)    # List[Device]
    device_found = Signal(object)
    progress_update = Signal(int, int, str)
    scan_started = Signal(int, str)
    partial = Signal(list)

    def __init__(
        self,
        cidrs: List[ipaddress.IPv4Network],
        cidr_label: str,
        iface_name: Optional[str],
        do_ping: bool,
        do_mdns: bool,
        do_ssdp: bool,
        do_rdns: bool,
        fetch_upnp_xml: bool,
        mdns_duration_s: int,
        ssdp_timeout_s: int,
        arp_timeout: float,
        arp_retries: int,
        icmp_timeout: float,
        icmp_retries: int,
        tcp_timeout: float,
        concurrency: int,
        oui_map: Dict[str, str],
        parent=None
    ):
        super().__init__(parent)
        self.cidrs = cidrs
        self.cidr_label = cidr_label
        self.iface_name = iface_name
        self.do_ping = do_ping
        self.do_mdns = do_mdns
        self.do_ssdp = do_ssdp
        self.do_rdns = do_rdns
        self.fetch_upnp_xml = fetch_upnp_xml
        self.mdns_duration_s = mdns_duration_s
        self.ssdp_timeout_s = ssdp_timeout_s
        self.arp_timeout = max(0.2, arp_timeout)
        self.arp_retries = max(0, arp_retries)
        self.icmp_timeout = max(0.2, icmp_timeout)
        self.icmp_retries = max(0, icmp_retries)
        self.tcp_timeout = max(0.1, tcp_timeout)
        self.concurrency = max(1, concurrency)
        self.oui_map = oui_map
        self._stop_event = threading.Event()
        self._last_emitted_state: Dict[str, Tuple] = {}
        self._partial_buffer: List[Device] = []
        self._last_partial_emit = time.time()

    def stop(self):
        self._stop_event.set()

    def _should_stop(self) -> bool:
        return self._stop_event.is_set()

    def _queue_update(self, device: Device):
        if device.mac:
            device.vendor = vendor_from_mac(device.mac, self.oui_map)
        state = (
            device.mac,
            device.vendor,
            device.hostname,
            device.rtt_ms,
            tuple(sorted(device.protocols)),
            tuple(sorted(device.sources)),
            device.description,
            device.ssdp_server,
            device.ssdp_st,
            device.ssdp_usn,
            device.ssdp_location,
            tuple(sorted(device.mdns_names)),
        )
        if self._last_emitted_state.get(device.ip) != state:
            self._last_emitted_state[device.ip] = state
            self.device_found.emit(device)
            self._partial_buffer.append(device)
            now = time.time()
            if now - self._last_partial_emit > 0.25:
                self.partial.emit(list(self._partial_buffer))
                self._partial_buffer.clear()
                self._last_partial_emit = now

    def _flush_pending(self, force: bool = False):
        # Maintained for backward compatibility; live updates handled via device_found.
        return

    def _deep_packet_inspection(self, devices: Dict[str, Device], npcap_available: bool):
        if (
            self._should_stop()
            or not npcap_available
            or not self.iface_name
            or not sniff
            or not ARP
            or not SCAPY_AVAILABLE
        ):
            return

        try:
            resolved_iface = resolve_capture_interface(self.iface_name)
        except Exception:
            resolved_iface = self.iface_name

        if not resolved_iface:
            return

        self.status.emit("Inspecting packets for duplicate IP/MAC mappings...")

        mac_to_ips: Dict[str, Set[str]] = defaultdict(set)
        ip_to_macs: Dict[str, Set[str]] = defaultdict(set)

        def record(ip: Optional[str], mac: Optional[str]):
            if not ip or not mac:
                return
            if not ip_in_networks(ip, self.cidrs):
                return
            mac_to_ips[mac].add(ip)
            ip_to_macs[ip].add(mac)

        for d in devices.values():
            record(d.ip, d.mac)

        try:
            packets = sniff(filter="arp", iface=resolved_iface, timeout=2, store=True, promisc=True)
        except Exception:
            packets = []

        for pkt in packets:
            try:
                arp_layer = pkt[ARP] if pkt.haslayer(ARP) else None
                if not arp_layer:
                    continue
                record(getattr(arp_layer, "psrc", None), getattr(arp_layer, "hwsrc", None))
                record(getattr(arp_layer, "pdst", None), getattr(arp_layer, "hwdst", None))
            except Exception:
                continue

        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                info = f"MAC {mac} seen on multiple IPs: {', '.join(sorted(ips))}"
                for ip in ips:
                    dev = self._merge_device(devices, ip)
                    if not dev.mac:
                        dev.mac = mac
                    dev.protocols.add("DPI")
                    dev.sources.add("DPI")
                    dev.description = normalize_description(dev.description, info)
                    self._queue_update(dev)

        for ip, macs in ip_to_macs.items():
            if len(macs) > 1:
                info = f"IP {ip} associated with multiple MACs: {', '.join(sorted(macs))}"
                dev = self._merge_device(devices, ip)
                if not dev.mac:
                    dev.mac = sorted(macs)[0]
                dev.protocols.add("DPI")
                dev.sources.add("DPI")
                dev.description = normalize_description(dev.description, info)
                self._queue_update(dev)

    def _merge_device(self, devices: Dict[str, Device], ip: str) -> Device:
        d = devices.get(ip)
        if not d:
            d = Device(ip=ip)
            devices[ip] = d
        d.last_seen_ts = time.time()
        return d

    def run(self):
        original_iface = conf.iface if conf else None
        try:
            if conf and self.iface_name:
                conf.iface = self.iface_name

            devices: Dict[str, Device] = {}

            npcap_available = is_npcap_available()
            target_ips: List[str] = []
            for net in self.cidrs:
                target_ips.extend(str(ip) for ip in net.hosts())

            total_targets = len(target_ips)
            self.scan_started.emit(total_targets, self.cidr_label)
            arp_ips: Set[str] = set()
            icmp_ips: Set[str] = set()
            tcp_ips: Set[str] = set()
            done_count = 0

            # Phase 0: Neighbor cache import
            self.status.emit("Importing neighbor cache...")
            arp_table = parse_arp_table()
            for ip, mac in arp_table.items():
                if not ip_in_networks(ip, self.cidrs):
                    continue
                dev = self._merge_device(devices, ip)
                if is_valid_mac(mac):
                    dev.mac = mac
                dev.protocols.add("NeighborCache")
                dev.sources.add("NeighborCache")
                self._queue_update(dev)
            done_count = min(len(devices), total_targets)
            self.progress_update.emit(done_count, total_targets, "Neighbor cache")

            # Phase 1: ARP sweep
            if npcap_available and conf and Ether and ARP and srp:
                conf.verb = 0
                for net in self.cidrs:
                    if self._should_stop():
                        self.status.emit("Scan stopped.")
                        return
                    self.status.emit(f"Scanning {net} (ARP sweep)...")
                    targets = [str(ip) for ip in net.hosts()]
                    batch_size = 256 if net.prefixlen >= 24 else 512
                    for i in range(0, len(targets), batch_size):
                        if self._should_stop():
                            self.status.emit("Scan stopped.")
                            return
                        batch = targets[i:i + batch_size]
                        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=batch)
                        ans, _ = srp(
                            pkt,
                            timeout=self.arp_timeout,
                            retry=self.arp_retries,
                            inter=0.005,
                        )
                        for snd, rcv in ans:
                            ip = getattr(rcv, "psrc", None)
                            mac = getattr(rcv, "hwsrc", None)
                            if not ip or not ip_in_networks(ip, self.cidrs):
                                continue
                            d = self._merge_device(devices, ip)
                            if is_valid_mac(mac):
                                d.mac = mac
                            if hasattr(rcv, "time") and hasattr(snd, "sent_time"):
                                try:
                                    rtt_ms = max(0.0, (float(rcv.time) - float(snd.sent_time)) * 1000)
                                    d.rtt_ms = rtt_ms if d.rtt_ms is None else min(d.rtt_ms, rtt_ms)
                                except Exception:
                                    pass
                            d.protocols.add("ARP")
                            d.sources.add("ARP")
                            arp_ips.add(ip)
                            self._queue_update(d)
                        done_count += len(batch)
                        pct = int((done_count / total_targets) * 100) if total_targets else 0
                        self.status.emit(
                            f"ARP sweep progress: {done_count}/{total_targets} ({pct}%)"
                        )
                        self.progress_update.emit(done_count, total_targets, "ARP sweep")
                self.status.emit(f"ARP replies: {len(arp_ips)}, Total unique: {len(devices)}")
            elif npcap_available:
                self.status.emit("ARP disabled (scapy unavailable).")
            else:
                self.status.emit("ARP disabled (Npcap not available).")

            # Phase 2: ICMP (conditional)
            remaining_for_icmp = [ip for ip in target_ips if ip not in devices]
            icmp_skipped = False
            if self.do_ping and remaining_for_icmp and not self._should_stop():
                if total_targets > 1024 and len(devices) > int(0.15 * total_targets):
                    icmp_skipped = True
                    self.status.emit("ICMP skipped (enough hosts found).")
                    done_count += len(remaining_for_icmp)
                    self.progress_update.emit(done_count, total_targets, "ICMP skipped")
                else:
                    self.status.emit(f"Pinging {len(remaining_for_icmp)} hosts (ICMP)...")

                    def icmp_probe(ip: str) -> Optional[Tuple[str, Optional[float]]]:
                        if self._should_stop():
                            return None
                        rtt_val: Optional[float] = None
                        try:
                            for _ in range(self.icmp_retries + 1):
                                r = ping(ip, timeout=self.icmp_timeout, unit="ms")
                                if r is not None:
                                    rtt_val = float(r)
                                    return ip, rtt_val
                        except PermissionError:
                            pass
                        except Exception:
                            pass

                        try:
                            if os.name == "nt":
                                cmd = ["ping", "-n", "1", "-w", str(int(self.icmp_timeout * 1000)), ip]
                            else:
                                cmd = ["ping", "-c", "1", "-W", str(int(max(1.0, self.icmp_timeout))), ip]
                            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.icmp_timeout + 1)
                            if proc.returncode == 0:
                                return ip, None
                        except Exception:
                            return None
                        return None

                    last_prog = time.time()
                    with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                        futures = {pool.submit(icmp_probe, ip): ip for ip in remaining_for_icmp}
                        for fut in as_completed(futures):
                            if self._should_stop():
                                self.status.emit("Scan stopped.")
                                return
                            res = fut.result()
                            if res:
                                ip, rtt = res
                                d = self._merge_device(devices, ip)
                                if rtt is not None:
                                    d.rtt_ms = rtt if d.rtt_ms is None else min(d.rtt_ms, rtt)
                                d.protocols.add("ICMP")
                                d.sources.add("ICMP")
                                icmp_ips.add(ip)
                                self._queue_update(d)
                            done_count += 1
                            now = time.time()
                            if now - last_prog > 0.1:
                                self.progress_update.emit(done_count, total_targets, "ICMP")
                                last_prog = now
                    self.progress_update.emit(done_count, total_targets, "ICMP")
                    self.status.emit(f"ICMP reachable: {len(icmp_ips)}, Total unique: {len(devices)}")
            elif self.do_ping and not remaining_for_icmp:
                self.status.emit("Skipping ICMP: all targets already identified via ARP.")
            else:
                icmp_skipped = not self.do_ping

            # Phase 3: TCP quick probe
            remaining_for_tcp = [ip for ip in target_ips if ip not in devices]
            if (not self.do_ping or icmp_skipped) and remaining_for_tcp and not self._should_stop():
                self.status.emit(f"Probing {len(remaining_for_tcp)} hosts (TCP)...")
                ports = [80, 443, 445, 3389, 22]

                def tcp_probe(ip: str) -> Optional[Tuple[str, Optional[int]]]:
                    if self._should_stop():
                        return None
                    for port in ports:
                        try:
                            start = time.time()
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(self.tcp_timeout)
                            r = sock.connect_ex((ip, port))
                            sock.close()
                            if r in (0, 111):
                                rtt_ms = (time.time() - start) * 1000
                                return ip, int(rtt_ms)
                        except Exception:
                            continue
                    return None

                last_prog = time.time()
                max_workers = min(128, self.concurrency * 2)
                with ThreadPoolExecutor(max_workers=max_workers) as pool:
                    futures = {pool.submit(tcp_probe, ip): ip for ip in remaining_for_tcp}
                    for fut in as_completed(futures):
                        if self._should_stop():
                            self.status.emit("Scan stopped.")
                            return
                        res = fut.result()
                        if res:
                            ip, rtt_ms = res
                            d = self._merge_device(devices, ip)
                            if rtt_ms is not None:
                                d.rtt_ms = rtt_ms if d.rtt_ms is None else min(d.rtt_ms, rtt_ms)
                            d.protocols.add("TCP")
                            d.sources.add("TCP")
                            tcp_ips.add(ip)
                            self._queue_update(d)
                        done_count += 1
                        now = time.time()
                        if now - last_prog > 0.1:
                            self.progress_update.emit(done_count, total_targets, "TCP")
                            last_prog = now
                self.progress_update.emit(done_count, total_targets, "TCP")
                self.status.emit(f"TCP responsive: {len(tcp_ips)}, Total unique: {len(devices)}")

            self._flush_pending(force=True)

            # Phase 4: Enrichment (for found devices only)
            if self.do_ssdp and not self._should_stop():
                self.status.emit("Discovering UPnP / SSDP devices...")
                self.progress_update.emit(done_count, total_targets, "SSDP")
                ssdp = ssdp_discover(timeout_s=self.ssdp_timeout_s)
                for ip, info in ssdp.items():
                    if not ip_in_networks(ip, self.cidrs):
                        continue
                    d = self._merge_device(devices, ip)
                    d.protocols.add("SSDP")
                    d.sources.add("SSDP")
                    d.ssdp_server = info.get("server")
                    d.ssdp_st = info.get("st")
                    d.ssdp_usn = info.get("usn")
                    d.ssdp_location = info.get("location")
                    d.description = normalize_description(d.description, info.get("server"))
                    self._queue_update(d)

                if self.fetch_upnp_xml and not self._should_stop():
                    max_workers = 16

                    def fetch_with_ip(ip: str, url: str) -> Optional[Tuple[str, str]]:
                        if self._should_stop() or not url:
                            return None
                        friendly_name = fetch_upnp_friendly_name(url)
                        if friendly_name:
                            return ip, friendly_name
                        return None

                    with ThreadPoolExecutor(max_workers=max_workers) as pool:
                        futures = {
                            pool.submit(fetch_with_ip, ip, info.get("location"))
                            for ip, info in ssdp.items()
                            if info.get("location") and ip_in_networks(ip, self.cidrs)
                        }
                        for fut in as_completed(futures):
                            if self._should_stop():
                                for pending in futures:
                                    pending.cancel()
                                self.status.emit("Scan stopped.")
                                return
                            res = fut.result()
                            if res:
                                ip, friendly = res
                                d = self._merge_device(devices, ip)
                                d.description = normalize_description(d.description, friendly)
                                self._queue_update(d)

            if self.do_mdns and not self._should_stop():
                self.status.emit("Collecting mDNS / Bonjour advertisements...")
                self.progress_update.emit(done_count, total_targets, "mDNS")
                mdns = MDNSCollector(duration_s=self.mdns_duration_s)
                names, services = mdns.run()

                for ip, name_set in names.items():
                    if not ip_in_networks(ip, self.cidrs):
                        continue
                    d = self._merge_device(devices, ip)
                    d.protocols.add("mDNS")
                    d.sources.add("mDNS")
                    d.mdns_names.update(name_set)
                    if not d.hostname and name_set:
                        d.hostname = sorted(name_set)[0]
                    d.description = normalize_description(d.description, ", ".join(sorted(name_set)))
                    self._queue_update(d)

                for ip, svc_set in services.items():
                    if not ip_in_networks(ip, self.cidrs):
                        continue
                    d = self._merge_device(devices, ip)
                    d.protocols.add("mDNS")
                    d.sources.add("mDNS")
                    d.description = normalize_description(d.description, f"Services: {', '.join(sorted(svc_set))}")
                    self._queue_update(d)
                self._flush_pending(force=True)

            if self.do_rdns and not self._should_stop():
                self.status.emit("Resolving hostnames (Reverse DNS)...")
                self.progress_update.emit(done_count, total_targets, "rDNS")
                targets = [d for d in devices.values() if not d.hostname]
                max_workers = min(64, max(4, self.concurrency))

                def rdns_lookup(ip: str) -> Optional[Tuple[str, str]]:
                    if self._should_stop():
                        return None
                    name = safe_gethostbyaddr(ip)
                    if name:
                        return ip, name
                    return None

                with ThreadPoolExecutor(max_workers=max_workers) as pool:
                    futures = [pool.submit(rdns_lookup, d.ip) for d in targets]
                    for fut in as_completed(futures):
                        if self._should_stop():
                            for pending in futures:
                                pending.cancel()
                            self.status.emit("Scan stopped.")
                            return
                        res = fut.result()
                        if res:
                            ip, name = res
                            dev = self._merge_device(devices, ip)
                            dev.hostname = name
                            dev.protocols.add("rDNS")
                            dev.sources.add("rDNS")
                            self._queue_update(dev)

            self.status.emit(
                f"ARP replies: {len(arp_ips)}, ICMP: {len(icmp_ips)}, TCP: {len(tcp_ips)}, Total unique: {len(devices)}"
            )
            if self._partial_buffer:
                self.partial.emit(list(self._partial_buffer))
                self._partial_buffer.clear()
            self.result.emit(list(devices.values()))
            self.finished_ok.emit()

        except PermissionError:
            self.status.emit("Error: Permission denied. Run as Administrator (and ensure Npcap installed).")
        except Exception as e:
            self.status.emit(f"Error: {e}")
        finally:
            if conf is not None and original_iface is not None:
                conf.iface = original_iface


class BackgroundDiscoveryWorker(QThread):
    device_found = Signal(object)
    status = Signal(str)

    def __init__(self, cidrs: List[ipaddress.IPv4Network], known_ips: List[str]):
        super().__init__()
        self.cidrs = cidrs
        self.known_ips = known_ips
        self._stop_event = threading.Event()
        self._index = 0

    def stop(self):
        self._stop_event.set()

    def _iter_hosts(self) -> List[str]:
        sample: List[str] = []
        for net in self.cidrs:
            hosts = list(net.hosts())
            if not hosts:
                continue
            start = self._index % len(hosts)
            chunk = hosts[start:start + 32]
            sample.extend(str(ip) for ip in chunk)
            self._index += 32
            break
        return sample

    def run(self):
        while not self._stop_event.is_set():
            targets = list(self.known_ips) + self._iter_hosts()
            for ip in targets:
                if self._stop_event.is_set():
                    break
                try:
                    rtt = ping(ip, timeout=1)
                except Exception:
                    rtt = None
                if rtt is None:
                    continue
                dev = Device(ip=ip, rtt_ms=rtt * 1000 if isinstance(rtt, (float, int)) else None)
                dev.sources.add("Background")
                dev.protocols.add("ICMP")
                self.device_found.emit(dev)
            for _ in range(10):
                if self._stop_event.is_set():
                    break
                time.sleep(0.2)


# -----------------------------
# GUI
# -----------------------------
CARD_RADIUS = 12


def set_badge(lbl: QLabel, state: str, text: str, size: str = "lg"):
    lbl.setObjectName("badge")
    lbl.setProperty("badgeState", state)
    lbl.setProperty("badgeSize", size)
    lbl.setText(text)
    lbl.setAlignment(Qt.AlignCenter)
    lbl.style().unpolish(lbl)
    lbl.style().polish(lbl)
    lbl.update()


class Card(QWidget):
    def __init__(self, title: str = "", parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)
        self.title_label: Optional[QLabel] = None
        self.header_layout: Optional[QHBoxLayout] = None
        if title:
            self.title_label = QLabel(title)
            self.title_label.setObjectName("cardTitle")
            self.header_layout = QHBoxLayout()
            self.header_layout.setContentsMargins(0, 0, 0, 0)
            self.header_layout.setSpacing(8)
            self.header_layout.addWidget(self.title_label)
            self.header_layout.addStretch(1)
            layout.addLayout(self.header_layout)
        self.content_layout = QVBoxLayout()
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(12)
        layout.addLayout(self.content_layout)


GLOBAL_QSS = f"""
QMainWindow {{
    background: #F6F7FB;
}}

QTabWidget::pane {{
    border: 0;
}}

QTabBar::tab {{
    background: transparent;
    padding: 8px 16px;
    margin-right: 4px;
    color: #6B7280;
    border-bottom: 2px solid transparent;
    font-weight: 600;
}}

QTabBar::tab:selected {{
    color: #111827;
    border-bottom: 2px solid #2563EB;
}}

QWidget#card, QGroupBox {{
    background: #FFFFFF;
    border: 1px solid #E5E7EB;
    border-radius: {CARD_RADIUS}px;
    padding: 2px;
}}

QGroupBox {{
    margin-top: 12px;
    padding-top: 18px;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
    padding: 0px 4px;
    color: #111827;
    font-weight: 600;
    background: transparent;
}}

QLabel#pageTitle {{
    font-size: 18px;
    font-weight: 600;
    color: #111827;
}}

QLabel#cardTitle, QLabel#sectionTitle {{
    font-size: 14px;
    font-weight: 600;
    color: #111827;
}}

QLabel#keyLabel {{
    color: #6B7280;
    font-size: 12px;
}}

QLabel#valueLabel {{
    color: #111827;
    font-size: 12px;
    font-weight: 600;
}}

QLabel#hintLabel {{
    color: #9CA3AF;
    font-size: 11px;
}}

QLabel#badge {{
    border-radius: 999px;
    font-weight: 700;
    background: #E5E7EB;
    color: #374151;
    min-width: 80px;
}}

QLabel#badge[badgeSize="lg"] {{
    padding: 6px 12px;
    font-size: 12px;
    min-height: 26px;
}}

QLabel#badge[badgeSize="sm"] {{
    padding: 3px 8px;
    font-size: 11px;
    min-height: 20px;
    min-width: 64px;
}}

QLabel#badge[badgeState="green"] {{
    background: #DCFCE7;
    color: #166534;
}}

QLabel#badge[badgeState="red"] {{
    background: #FEE2E2;
    color: #991B1B;
}}

QLabel#badge[badgeState="yellow"] {{
    background: #FEF3C7;
    color: #92400E;
}}

QLabel#badge[badgeState="gray"] {{
    background: #E5E7EB;
    color: #374151;
}}

QLabel#badge[badgeState="blue"] {{
    background: #DBEAFE;
    color: #1D4ED8;
}}

QPushButton {{
    background: #2563EB;
    color: white;
    border-radius: 10px;
    padding: 8px 14px;
    border: 1px solid #2563EB;
    font-weight: 600;
}}

QPushButton:hover {{
    background: #1D4ED8;
    border-color: #1D4ED8;
}}

QPushButton:disabled {{
    background: #9CA3AF;
    border-color: #9CA3AF;
    color: #F3F4F6;
}}

QPushButton#ghostButton {{
    background: transparent;
    color: #2563EB;
    border: 1px solid #E5E7EB;
}}

QPushButton#secondaryButton {{
    background: #EEF2FF;
    color: #1D4ED8;
    border: 1px solid #C7D2FE;
}}

QPushButton#secondaryButton:hover {{
    background: #E0E7FF;
    border-color: #A5B4FC;
}}

QPushButton#dangerButton {{
    background: #EF4444;
    border: 1px solid #EF4444;
}}

QPushButton#dangerButton:hover {{
    background: #DC2626;
    border-color: #DC2626;
}}

QPushButton#linkButton {{
    background: transparent;
    color: #2563EB;
    border: none;
    padding: 0px;
    font-weight: 600;
}}

QPushButton#linkButton:hover {{
    text-decoration: underline;
}}

QLineEdit, QSpinBox, QComboBox, QPlainTextEdit, QTableWidget {{
    border: 1px solid #E5E7EB;
    border-radius: 8px;
    padding: 6px 8px;
    background: #FFFFFF;
}}

QPlainTextEdit#console {{
    background: #111827;
    color: #E5E7EB;
    border: 1px solid #0F172A;
    border-radius: 12px;
    font-family: "Consolas", "Courier New", monospace;
    padding: 10px;
}}

QTableWidget {{
    border-radius: 12px;
    gridline-color: #E5E7EB;
}}

QHeaderView::section {{
    background: #F3F4F6;
    color: #111827;
    padding: 8px 6px;
    border: 0px;
    border-bottom: 1px solid #E5E7EB;
}}

QHeaderView::section:horizontal {{
    border-top-left-radius: 12px;
    border-top-right-radius: 12px;
}}

QFrame#metricTile, QWidget#metricTile {{
    background: #FFFFFF;
    border: 1px solid #E5E7EB;
    border-radius: 12px;
    padding: 12px;
}}

QLabel#tileTitle {{
    font-size: 12px;
    color: #6B7280;
}}
"""

class DiagnosticsWorker(QThread):
    diagOutputLine = Signal(str)
    diagStatusChanged = Signal(str)
    diagRunningChanged = Signal(bool)

    def __init__(self, command: List[str]):
        super().__init__()
        self.command = command
        self.process: Optional[subprocess.Popen] = None
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
            except Exception:
                pass

    def run(self):
        status = "Running"
        self.diagRunningChanged.emit(True)
        self.diagStatusChanged.emit(status)
        try:
            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            if not self.process.stdout:
                raise RuntimeError("No output stream")

            for raw_line in self.process.stdout:
                if self._stop_event.is_set():
                    status = "Stopped"
                    break
                self.diagOutputLine.emit(raw_line.rstrip())

            if self._stop_event.is_set() and self.process.poll() is None:
                try:
                    self.process.terminate()
                except Exception:
                    pass

            if status == "Running":
                ret = self.process.wait()
                status = "Completed" if ret == 0 else "Failed"
        except Exception as e:
            status = f"Failed: {e}"
        finally:
            self.diagStatusChanged.emit(status)
            self.diagRunningChanged.emit(False)


class Layer2InfoWorker(QThread):
    result = Signal(dict)

    def __init__(self, iface_name: Optional[str]):
        super().__init__()
        self.iface_name = iface_name

    def run(self):
        payload = {
            "lldp": {"status": "Unknown"},
            "vlans": {"status": "Unknown", "vlans": []},
            "meta": {
                "iface": self.iface_name or "-",
                "captured": 0,
                "lldp_frames": 0,
                "vlan_frames": 0,
                "error": None,
            },
        }

        if not self.iface_name or not sniff or not SCAPY_AVAILABLE:
            self.result.emit(payload)
            return

        try:
            resolved_iface = resolve_capture_interface(self.iface_name)
            payload["meta"]["iface"] = resolved_iface or self.iface_name
            packets = sniff(iface=resolved_iface, timeout=3, store=True, promisc=True)
        except Exception as e:
            payload["lldp"]["status"] = "Layer 2 capture: Unavailable (requires Npcap + permissions)"
            payload["vlans"]["status"] = "Unknown (capture failed)"
            payload["meta"]["error"] = str(e)
            self.result.emit(payload)
            return

        payload["meta"]["captured"] = len(packets)
        lldp_detected = False
        lldp_details: Dict[str, str] = {}
        vlan_ids: Set[int] = set()
        lldp_frames = 0
        vlan_frame_count = 0

        for pkt in packets:
            try:
                eth = pkt.getlayer(Ether)
                if not eth:
                    continue

                eth_type = getattr(eth, "type", None)
                dst_mac = getattr(eth, "dst", "").lower()

                if eth_type == 0x88CC or dst_mac == "01:80:c2:00:00:0e":
                    lldp_detected = True
                    lldp_frames += 1
                    raw = bytes(pkt.payload)
                    parsed = parse_lldp_tlvs(raw)
                    for k, v in parsed.items():
                        if v:
                            lldp_details.setdefault(k, v)

                vlan_layer = pkt[Dot1Q] if Dot1Q and pkt.haslayer(Dot1Q) else None
                if vlan_layer or eth_type == 0x8100:
                    vlan_frame_count += 1
                    vlan_id = getattr(vlan_layer, "vlan", None)
                    if vlan_id is not None:
                        vlan_ids.add(int(vlan_id))
            except Exception:
                continue

        payload["meta"]["lldp_frames"] = lldp_frames
        payload["meta"]["vlan_frames"] = vlan_frame_count
        payload["lldp"]["status"] = "Detected" if lldp_detected else "Not detected"
        payload["lldp"].update(lldp_details)

        if vlan_ids:
            payload["vlans"]["status"] = "Detected"
            payload["vlans"]["vlans"] = sorted(vlan_ids)
        else:
            payload["vlans"]["status"] = "None detected"
        self.result.emit(payload)


class AVInsightsWorker(QThread):
    avInsightsUpdated = Signal(dict)
    avEvidenceLine = Signal(str)

    def __init__(self, iface_name: Optional[str]):
        super().__init__()
        self.iface_name = iface_name

    def run(self):
        payload = {
            "multicast": "Unknown",
            "igmp": "Unknown",
            "igmp_querier": "Unknown",
            "ptp": "Unknown",
            "dante": "Unknown",
            "nvx": "Unknown",
        }

        if not self.iface_name or not sniff or not SCAPY_AVAILABLE:
            self.avInsightsUpdated.emit(payload)
            return

        try:
            packets = sniff(iface=self.iface_name, timeout=3, store=True)
        except Exception:
            self.avInsightsUpdated.emit(payload)
            return

        summary, evidence = summarize_multicast_evidence(packets)
        self.avInsightsUpdated.emit(summary)
        for line in evidence[:30]:
            self.avEvidenceLine.emit(line)


class MainWindow(QMainWindow):
    externalIpChanged = Signal(str)
    internetStatusChanged = Signal(bool)
    igmpStatusChanged = Signal(dict)
    envStatusChanged = Signal(dict)

    ONLINE_TTL_SEC = 30
    STALE_TTL_SEC = 120
    OFFLINE_AFTER_SEC = 300

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Local Network Device Discovery (Windows)")
        self.resize(1180, 680)
        self.apply_stylesheet()

        self.oui_map = load_oui_map("oui.csv")
        self.worker: Optional[ScanWorker] = None
        self.devices: List[Device] = []
        self.devices_map: Dict[str, Device] = {}
        self.devices_by_key: Dict[str, Device] = {}
        self.ip_to_key: Dict[str, str] = {}
        self._row_by_key: Dict[str, int] = {}
        self._pending_updates: Dict[str, Device] = {}
        self._update_timer = QTimer(self)
        self._update_timer.setInterval(200)
        self._update_timer.timeout.connect(self.flush_pending_updates)
        self.npcap_available = False
        self.last_connectivity_state: Optional[bool] = None
        self.last_connectivity_ts: float = 0.0
        self.igmp_check_running = False
        self.env_check_running = False
        self.l2_check_running = False
        self.av_check_running = False
        self.last_network_snapshot: Dict[str, str] = {}
        self.network_last_updated_ts: Optional[float] = None
        self.diag_worker: Optional[DiagnosticsWorker] = None
        self.l2_worker: Optional[Layer2InfoWorker] = None
        self.av_worker: Optional[AVInsightsWorker] = None
        self.presence_timer = QTimer(self)
        self.presence_timer.setInterval(1000)
        self.presence_timer.timeout.connect(self._tick_presence)
        self.presence_timer.start()
        self.live_feed_lines: List[str] = []
        self.continuous_worker: Optional['BackgroundDiscoveryWorker'] = None
        self._last_presence_state: Dict[str, str] = {}

        self.externalIpChanged.connect(self.set_external_ip)
        self.internetStatusChanged.connect(self.set_connectivity_state)
        self.igmpStatusChanged.connect(self.apply_igmp_status)
        self.envStatusChanged.connect(self.apply_env_status)
        self.connectivity_check_running = False

        tabs = QTabWidget()
        self.setCentralWidget(tabs)

        self.network_tab = self.build_network_info_tab()
        self.scan_tab = self.build_scan_tab()
        self.diagnostics_tab = self.build_diagnostics_tab()
        self.av_tab = self.build_av_tab()

        tabs.addTab(self.network_tab, "Network Info")
        tabs.addTab(self.scan_tab, "Scan")
        tabs.addTab(self.diagnostics_tab, "Diagnostics")
        tabs.addTab(self.av_tab, "AV / Multicast Insights")

        self.load_interfaces()

        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_export.clicked.connect(self.export_csv)
        self.btn_install_npcap.clicked.connect(self.open_npcap_download)
        self.if_combo.currentIndexChanged.connect(self.on_interface_changed)
        self.btn_network_refresh.clicked.connect(lambda: self.refresh_network_info(force=True))
        self.btn_env_refresh.clicked.connect(self.run_env_checks)
        self.btn_diag_ping.clicked.connect(self.run_diag_ping)
        self.btn_diag_traceroute.clicked.connect(self.run_diag_traceroute)
        self.btn_diag_stop.clicked.connect(self.stop_diag_worker)
        self.btn_l2_refresh.clicked.connect(self.run_l2_check)
        self.l2_toggle_btn.clicked.connect(self.toggle_l2_debug)
        self.cb_continuous.stateChanged.connect(self.on_continuous_changed)
        self.cb_online_only.stateChanged.connect(lambda _: self.flush_pending_updates())

        self.update_npcap_state()
        self.fetch_external_ip()
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
        self.network_monitor_timer = QTimer(self)
        self.network_monitor_timer.setInterval(4000)
        self.network_monitor_timer.timeout.connect(self.refresh_network_info)
        self.network_monitor_timer.start()
        self.network_timestamp_timer = QTimer(self)
        self.network_timestamp_timer.setInterval(1000)
        self.network_timestamp_timer.timeout.connect(self._update_network_updated_label)
        self.network_timestamp_timer.start()
        self._update_timer.start()
        self.on_interface_changed(self.if_combo.currentIndex())

    def apply_stylesheet(self):
        app = QApplication.instance()
        if app:
            app.setStyleSheet(GLOBAL_QSS)

    def build_network_info_tab(self) -> QWidget:
        widget = QWidget()
        root_layout = QVBoxLayout(widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        root_layout.addWidget(scroll_area)

        scroll_content = QWidget()
        scroll_area.setWidget(scroll_content)

        layout = QVBoxLayout(scroll_content)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        header_row = QHBoxLayout()
        header_row.setSpacing(10)
        title = QLabel("Network Overview")
        title.setObjectName("pageTitle")
        header_row.addWidget(title)
        header_row.addStretch(1)
        self.network_updated_lbl = QLabel("Last updated: -")
        self.network_updated_lbl.setObjectName("hintLabel")
        header_row.addWidget(self.network_updated_lbl)
        self.btn_network_refresh = QPushButton("Refresh all")
        header_row.addWidget(self.btn_network_refresh)
        layout.addLayout(header_row)

        def make_label(text: str) -> QLabel:
            lbl = QLabel(text)
            lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            lbl.setObjectName("keyLabel")
            lbl.setFixedWidth(150)
            return lbl

        def make_value_label() -> QLabel:
            val = QLabel("-")
            val.setObjectName("valueLabel")
            val.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            val.setWordWrap(True)
            return val

        connection_card = Card("Connection")
        conn_layout = connection_card.content_layout
        internet_row = QHBoxLayout()
        internet_row.setSpacing(10)
        internet_lbl = QLabel("Internet")
        internet_lbl.setObjectName("keyLabel")
        internet_row.addWidget(internet_lbl)
        self.connectivity_lbl = QLabel()
        set_badge(self.connectivity_lbl, "gray", "Checking...", size="lg")
        internet_row.addWidget(self.connectivity_lbl)
        internet_row.addStretch(1)
        conn_layout.addLayout(internet_row)

        conn_grid = QGridLayout()
        conn_grid.setHorizontalSpacing(16)
        conn_grid.setVerticalSpacing(8)
        conn_grid.setContentsMargins(0, 0, 0, 0)

        self.external_ip_lbl = make_value_label()
        self.external_ip_lbl.setText("Fetching...")
        self.client_ip_lbl = make_value_label()
        self.interface_lbl = make_value_label()

        conn_grid.addWidget(make_label("External IP"), 0, 0)
        conn_grid.addWidget(self.external_ip_lbl, 0, 1)
        conn_grid.addWidget(make_label("Client IP"), 1, 0)
        conn_grid.addWidget(self.client_ip_lbl, 1, 1)
        conn_grid.addWidget(make_label("Interface"), 2, 0)
        conn_grid.addWidget(self.interface_lbl, 2, 1)
        conn_layout.addLayout(conn_grid)

        dhcp_card = Card("DHCP")
        dhcp_layout = dhcp_card.content_layout
        dhcp_labels = [
            ("DHCP Server", "dhcp_server"),
            ("Lease start", "lease_start"),
            ("Lease expiration", "lease_end"),
            ("Subnet mask", "subnet_mask"),
            ("Default gateway", "gateway"),
            ("DNS servers", "dns"),
        ]

        grid = QGridLayout()
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(8)
        grid.setContentsMargins(0, 0, 0, 0)
        self.dhcp_value_labels: Dict[str, QLabel] = {}
        for row, (title_text, key) in enumerate(dhcp_labels):
            label_widget = make_label(title_text)
            val_lbl = make_value_label()
            self.dhcp_value_labels[key] = val_lbl
            grid.addWidget(label_widget, row, 0)
            grid.addWidget(val_lbl, row, 1)
        dhcp_layout.addLayout(grid)

        left_column_widget = QWidget()
        left_column_widget.setMinimumWidth(520)
        left_column = QVBoxLayout(left_column_widget)
        left_column.setSpacing(14)
        left_column.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        left_column.addWidget(connection_card)
        left_column.addWidget(dhcp_card)

        right_column_widget = QWidget()
        right_column_widget.setMinimumWidth(520)
        right_column = QVBoxLayout(right_column_widget)
        right_column.setSpacing(14)
        right_column.setAlignment(Qt.AlignTop | Qt.AlignLeft)

        self.env_group = Card("Environment Status")
        env_layout = self.env_group.content_layout
        env_rows = []
        self.npcap_status_lbl = QLabel()
        self.admin_status_lbl = QLabel()
        self.arp_status_lbl = QLabel()
        env_rows.append(("Npcap", self.npcap_status_lbl))
        env_rows.append(("Administrator", self.admin_status_lbl))
        env_rows.append(("ARP", self.arp_status_lbl))
        for title_text, lbl in env_rows:
            row = QHBoxLayout()
            row.setSpacing(8)
            key_lbl = QLabel(title_text)
            key_lbl.setObjectName("keyLabel")
            row.addWidget(key_lbl)
            set_badge(lbl, "gray", "Unknown", size="sm")
            row.addWidget(lbl)
            row.addStretch(1)
            env_layout.addLayout(row)
        arp_hint = QLabel("ARP may require Admin and/or Npcap for best results.")
        arp_hint.setObjectName("hintLabel")
        env_layout.addWidget(arp_hint)
        if self.env_group.header_layout:
            self.btn_env_refresh = QPushButton("Refresh")
            self.env_group.header_layout.addWidget(self.btn_env_refresh)
        right_column.addWidget(self.env_group)

        self.igmp_group = Card("Multicast / IGMP")
        igmp_layout = self.igmp_group.content_layout
        igmp_metrics = [
            ("IGMP Snooping", "igmp_status_lbl"),
            ("IGMP Querier", "igmp_querier_lbl"),
        ]

        self.igmp_status_lbl = QLabel()
        self.igmp_status_lbl.setToolTip(
            "Best-effort inference; definitive snooping status requires switch/router access."
        )
        self.igmp_querier_lbl = QLabel()
        for title_text, attr_name in igmp_metrics:
            row = QHBoxLayout()
            row.setSpacing(8)
            label_widget = QLabel(title_text)
            label_widget.setObjectName("keyLabel")
            row.addWidget(label_widget)
            badge_lbl = getattr(self, attr_name)
            set_badge(badge_lbl, "gray", "Unknown")
            row.addWidget(badge_lbl)
            row.addStretch(1)
            igmp_layout.addLayout(row)
        right_column.addWidget(self.igmp_group)

        l2_group = Card("Layer 2 Info")
        l2_layout = QGridLayout()
        l2_layout.setHorizontalSpacing(16)
        l2_layout.setVerticalSpacing(8)
        l2_layout.setContentsMargins(0, 0, 0, 0)

        self.lldp_status_lbl = QLabel()
        set_badge(self.lldp_status_lbl, "gray", "LLDP: Unknown")
        self.lldp_chassis_lbl = make_value_label()
        self.lldp_port_lbl = make_value_label()
        self.lldp_sysname_lbl = make_value_label()
        self.lldp_portdesc_lbl = make_value_label()
        self.lldp_mgmt_lbl = make_value_label()
        self.vlan_status_badge = QLabel()
        set_badge(self.vlan_status_badge, "gray", "VLANs: Unknown")
        self.vlan_lbl = make_value_label()

        l2_layout.addWidget(make_label("LLDP Status"), 0, 0)
        l2_layout.addWidget(self.lldp_status_lbl, 0, 1)
        l2_layout.addWidget(make_label("Chassis ID"), 1, 0)
        l2_layout.addWidget(self.lldp_chassis_lbl, 1, 1)
        l2_layout.addWidget(make_label("Port ID"), 2, 0)
        l2_layout.addWidget(self.lldp_port_lbl, 2, 1)
        l2_layout.addWidget(make_label("System Name"), 3, 0)
        l2_layout.addWidget(self.lldp_sysname_lbl, 3, 1)
        l2_layout.addWidget(make_label("Port Description"), 4, 0)
        l2_layout.addWidget(self.lldp_portdesc_lbl, 4, 1)
        l2_layout.addWidget(make_label("Management Address"), 5, 0)
        l2_layout.addWidget(self.lldp_mgmt_lbl, 5, 1)
        l2_layout.addWidget(make_label("VLAN Status"), 6, 0)
        l2_layout.addWidget(self.vlan_status_badge, 6, 1)
        l2_layout.addWidget(make_label("VLAN Details"), 7, 0)
        l2_layout.addWidget(self.vlan_lbl, 7, 1)

        self.l2_iface_hint = QLabel("Capture interface: -")
        self.l2_iface_hint.setObjectName("hintLabel")
        self.l2_capture_hint = QLabel("Captured frames: 0")
        self.l2_capture_hint.setObjectName("hintLabel")
        self.l2_counts_hint = QLabel("LLDP frames: 0 | VLAN-tagged frames: 0")
        self.l2_counts_hint.setObjectName("hintLabel")

        self.l2_debug_container = QWidget()
        debug_layout = QVBoxLayout(self.l2_debug_container)
        debug_layout.setContentsMargins(8, 8, 8, 8)
        debug_layout.setSpacing(6)
        debug_layout.addWidget(self.l2_iface_hint)
        debug_layout.addWidget(self.l2_capture_hint)
        debug_layout.addWidget(self.l2_counts_hint)
        self.l2_debug_container.setVisible(False)

        toggle_row = QHBoxLayout()
        toggle_row.setContentsMargins(0, 0, 0, 0)
        toggle_row.addStretch(1)
        self.l2_toggle_btn = QPushButton("Show capture details")
        self.l2_toggle_btn.setObjectName("linkButton")
        self.l2_toggle_btn.setCursor(Qt.PointingHandCursor)
        toggle_row.addWidget(self.l2_toggle_btn)

        l2_group.content_layout.addLayout(l2_layout)
        l2_group.content_layout.addLayout(toggle_row)
        l2_group.content_layout.addWidget(self.l2_debug_container)
        if l2_group.header_layout:
            self.btn_l2_refresh = QPushButton("Refresh")
            l2_group.header_layout.addWidget(self.btn_l2_refresh)
        right_column.addWidget(l2_group)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(8)
        splitter.addWidget(left_column_widget)
        splitter.addWidget(right_column_widget)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        single_column_widget = QWidget()
        single_column_layout = QVBoxLayout(single_column_widget)
        single_column_layout.setSpacing(14)
        single_column_layout.setContentsMargins(0, 0, 0, 0)
        single_column_layout.setAlignment(Qt.AlignTop | Qt.AlignLeft)

        class ResponsiveContainer(QWidget):
            def __init__(self, outer: "MainWindow"):
                super().__init__()
                self.outer = outer
                self.breakpoint = 1100
                self.left_cards = [connection_card, dhcp_card]
                self.right_cards = [self.outer.env_group, self.outer.igmp_group, l2_group]
                container_layout = QVBoxLayout(self)
                container_layout.setContentsMargins(0, 0, 0, 0)
                container_layout.setSpacing(0)
                container_layout.addWidget(splitter)
                container_layout.addWidget(single_column_widget)
                single_column_widget.hide()

            def remove_widget_from_layout(self, layout_obj: QVBoxLayout, widget_obj: QWidget) -> None:
                for idx in range(layout_obj.count()):
                    item = layout_obj.itemAt(idx)
                    if item and item.widget() is widget_obj:
                        layout_obj.takeAt(idx)
                        return

            def move_widget_to_layout(self, layout_obj: QVBoxLayout, widget_obj: QWidget) -> None:
                for maybe_layout in (left_column, right_column, single_column_layout):
                    self.remove_widget_from_layout(maybe_layout, widget_obj)
                layout_obj.addWidget(widget_obj)

            def update_mode(self, width: int) -> None:
                if width < self.breakpoint:
                    if splitter.isVisible():
                        splitter.hide()
                    if not single_column_widget.isVisible():
                        single_column_widget.show()
                    for card in self.left_cards + self.right_cards:
                        self.move_widget_to_layout(single_column_layout, card)
                else:
                    if not splitter.isVisible():
                        splitter.show()
                    if single_column_widget.isVisible():
                        single_column_widget.hide()
                    for card in self.left_cards:
                        self.move_widget_to_layout(left_column, card)
                    for card in self.right_cards:
                        self.move_widget_to_layout(right_column, card)

            def resizeEvent(self, event):
                super().resizeEvent(event)
                self.update_mode(event.size().width())

        responsive_container = ResponsiveContainer(self)
        layout.addWidget(responsive_container)
        responsive_container.update_mode(self.width())
        return widget

    def build_scan_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        title = QLabel("Scan")
        title.setObjectName("pageTitle")
        layout.addWidget(title)

        controls_card = Card("Scan Controls")
        controls_layout = controls_card.content_layout

        header_bar = QHBoxLayout()
        header_bar.setSpacing(10)
        header_label = QLabel("Configure targets and run scans")
        header_label.setObjectName("sectionTitle")
        header_bar.addWidget(header_label)
        header_bar.addStretch(1)
        self.btn_scan = QPushButton("Start Scan")
        self.btn_stop = QPushButton("Stop Scan")
        self.btn_stop.setObjectName("dangerButton")
        self.btn_export = QPushButton("Export CSV")
        self.btn_export.setObjectName("secondaryButton")
        self.btn_install_npcap = QPushButton("Install Npcap")
        self.btn_install_npcap.setObjectName("ghostButton")
        self.btn_install_npcap.setVisible(False)
        self.btn_stop.setEnabled(False)
        header_bar.addWidget(self.btn_scan)
        header_bar.addWidget(self.btn_stop)
        header_bar.addWidget(self.btn_export)
        header_bar.addWidget(self.btn_install_npcap)
        controls_layout.addLayout(header_bar)

        config_form = QFormLayout()
        config_form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        config_form.setFormAlignment(Qt.AlignLeft | Qt.AlignTop)
        config_form.setHorizontalSpacing(12)
        config_form.setVerticalSpacing(8)

        self.if_combo = QComboBox()
        config_form.addRow(QLabel("Interface:"), self.if_combo)

        check_row = QWidget()
        check_layout = QHBoxLayout(check_row)
        check_layout.setContentsMargins(0, 0, 0, 0)
        check_layout.setSpacing(10)

        self.cb_ping = QCheckBox("Ping (ICMP)")
        self.cb_ping.setChecked(True)
        check_layout.addWidget(self.cb_ping)

        self.cb_mdns = QCheckBox("mDNS / Bonjour")
        self.cb_mdns.setChecked(True)
        check_layout.addWidget(self.cb_mdns)

        self.cb_ssdp = QCheckBox("UPnP / SSDP")
        self.cb_ssdp.setChecked(True)
        check_layout.addWidget(self.cb_ssdp)

        self.cb_rdns = QCheckBox("Reverse DNS")
        self.cb_rdns.setChecked(False)
        check_layout.addWidget(self.cb_rdns)

        self.cb_upnp_xml = QCheckBox("Fetch UPnP XML (friendlyName)")
        self.cb_upnp_xml.setChecked(False)
        check_layout.addWidget(self.cb_upnp_xml)
        self.cb_online_only = QCheckBox("Only show Online")
        self.cb_online_only.setChecked(True)
        check_layout.addWidget(self.cb_online_only)
        self.cb_continuous = QCheckBox("Continuous discovery (background)")
        self.cb_continuous.setChecked(False)
        check_layout.addWidget(self.cb_continuous)
        check_layout.addStretch(1)
        config_form.addRow(QLabel("Protocols:"), check_row)

        self.range_input = QLineEdit()
        self.range_input.setPlaceholderText("192.168.1.0/24 or 192.168.1.10-192.168.1.50")
        config_form.addRow(QLabel("Custom range (optional):"), self.range_input)

        timing_row = QWidget()
        timing_layout = QHBoxLayout(timing_row)
        timing_layout.setContentsMargins(0, 0, 0, 0)
        timing_layout.setSpacing(10)

        timing_layout.addWidget(QLabel("mDNS seconds:"))
        self.sp_mdns = QSpinBox()
        self.sp_mdns.setRange(2, 20)
        self.sp_mdns.setValue(5)
        timing_layout.addWidget(self.sp_mdns)

        timing_layout.addWidget(QLabel("SSDP timeout:"))
        self.sp_ssdp = QSpinBox()
        self.sp_ssdp.setRange(1, 10)
        self.sp_ssdp.setValue(3)
        timing_layout.addWidget(self.sp_ssdp)
        timing_layout.addStretch(1)
        config_form.addRow(QLabel("Timing:"), timing_row)

        ttl_group = QGroupBox("Presence TTL (advanced)")
        ttl_group.setCheckable(True)
        ttl_group.setChecked(False)
        ttl_layout = QHBoxLayout(ttl_group)
        ttl_layout.setContentsMargins(8, 8, 8, 8)
        ttl_layout.setSpacing(10)
        ttl_layout.addWidget(QLabel("Online TTL (sec)"))
        self.sp_online_ttl = QSpinBox()
        self.sp_online_ttl.setRange(5, 600)
        self.sp_online_ttl.setValue(self.ONLINE_TTL_SEC)
        ttl_layout.addWidget(self.sp_online_ttl)
        ttl_layout.addWidget(QLabel("Stale TTL (sec)"))
        self.sp_stale_ttl = QSpinBox()
        self.sp_stale_ttl.setRange(10, 1200)
        self.sp_stale_ttl.setValue(self.STALE_TTL_SEC)
        ttl_layout.addWidget(self.sp_stale_ttl)
        ttl_layout.addWidget(QLabel("Offline after (sec)"))
        self.sp_offline_ttl = QSpinBox()
        self.sp_offline_ttl.setRange(30, 3600)
        self.sp_offline_ttl.setValue(self.OFFLINE_AFTER_SEC)
        ttl_layout.addWidget(self.sp_offline_ttl)
        ttl_layout.addStretch(1)
        config_form.addRow(QLabel("Presence smoothing:"), ttl_group)

        advanced_row = QWidget()
        advanced_layout = QGridLayout(advanced_row)
        advanced_layout.setContentsMargins(0, 0, 0, 0)
        advanced_layout.setHorizontalSpacing(10)
        advanced_layout.setVerticalSpacing(6)

        self.sp_arp_timeout = QDoubleSpinBox()
        self.sp_arp_timeout.setDecimals(1)
        self.sp_arp_timeout.setRange(0.2, 5.0)
        self.sp_arp_timeout.setSingleStep(0.1)
        self.sp_arp_timeout.setValue(1.5)

        self.sp_arp_retries = QSpinBox()
        self.sp_arp_retries.setRange(0, 3)
        self.sp_arp_retries.setValue(1)

        self.sp_icmp_timeout = QDoubleSpinBox()
        self.sp_icmp_timeout.setDecimals(1)
        self.sp_icmp_timeout.setRange(0.2, 5.0)
        self.sp_icmp_timeout.setSingleStep(0.1)
        self.sp_icmp_timeout.setValue(1.0)

        self.sp_icmp_retries = QSpinBox()
        self.sp_icmp_retries.setRange(0, 3)
        self.sp_icmp_retries.setValue(1)

        self.sp_tcp_timeout = QDoubleSpinBox()
        self.sp_tcp_timeout.setDecimals(1)
        self.sp_tcp_timeout.setRange(0.1, 2.0)
        self.sp_tcp_timeout.setSingleStep(0.1)
        self.sp_tcp_timeout.setValue(0.35)

        self.sp_concurrency = QSpinBox()
        self.sp_concurrency.setRange(1, 256)
        self.sp_concurrency.setValue(64)

        advanced_layout.addWidget(QLabel("ARP timeout (s)"), 0, 0)
        advanced_layout.addWidget(self.sp_arp_timeout, 0, 1)
        advanced_layout.addWidget(QLabel("ARP retries"), 0, 2)
        advanced_layout.addWidget(self.sp_arp_retries, 0, 3)
        advanced_layout.addWidget(QLabel("ICMP timeout (s)"), 1, 0)
        advanced_layout.addWidget(self.sp_icmp_timeout, 1, 1)
        advanced_layout.addWidget(QLabel("ICMP retries"), 1, 2)
        advanced_layout.addWidget(self.sp_icmp_retries, 1, 3)
        advanced_layout.addWidget(QLabel("TCP timeout (s)"), 2, 0)
        advanced_layout.addWidget(self.sp_tcp_timeout, 2, 1)
        advanced_layout.addWidget(QLabel("Concurrency"), 2, 2)
        advanced_layout.addWidget(self.sp_concurrency, 2, 3)

        config_form.addRow(QLabel("Performance:"), advanced_row)

        controls_layout.addLayout(config_form)

        vendor_status = (
            f"Ready. Loaded {len(self.oui_map)} OUI prefixes."
            if self.oui_map
            else "Ready. MAC vendor lookup unavailable (oui.csv not loaded)."
        )
        status_row = QHBoxLayout()
        status_row.setSpacing(8)
        status_hint = QLabel("Status")
        status_hint.setObjectName("keyLabel")
        status_row.addWidget(status_hint)
        self.status_lbl = QLabel(vendor_status)
        self.status_lbl.setObjectName("valueLabel")
        status_row.addWidget(self.status_lbl)
        status_row.addStretch(1)
        controls_layout.addLayout(status_row)

        progress_row = QHBoxLayout()
        progress_row.setSpacing(8)
        progress_label = QLabel("Progress")
        progress_label.setObjectName("keyLabel")
        progress_row.addWidget(progress_label)
        self.progress_lbl = QLabel("Idle")
        self.progress_lbl.setObjectName("valueLabel")
        progress_row.addWidget(self.progress_lbl)
        progress_row.addStretch(1)
        controls_layout.addLayout(progress_row)
        layout.addWidget(controls_card)

        self.table = QTableWidget(0, 10)
        self.table.setHorizontalHeaderLabels(
            [
                "IP",
                "IPs (seen)",
                "Presence",
                "MAC Address",
                "MAC Vendor",
                "Hostname",
                "Ping (ms)",
                "Found By",
                "Protocols",
                "Description",
            ]
        )
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(False)
        self.table.setStyleSheet(
            """
QTableWidget {
    background-color: #ffffff;
    color: #000000;
    gridline-color: #d0d0d0;
    font-size: 13px;
}
QTableWidget::item { padding: 6px; }
QTableWidget::item:selected {
    background-color: #2f6fed;
    color: #ffffff;
}
QHeaderView::section {
    background-color: #f2f2f2;
    color: #000000;
    padding: 6px;
    border: 1px solid #d0d0d0;
    font-weight: 600;
}
"""
        )

        table_card = Card("Scan Results")
        summary_row = QHBoxLayout()
        self.presence_summary_lbl = QLabel("Online: 0 | Unknown: 0 | Offline: 0 | Total known: 0")
        summary_row.addWidget(self.presence_summary_lbl)
        summary_row.addStretch(1)
        table_card.content_layout.addLayout(summary_row)
        self.live_feed_toggle = QPushButton("Show Live Feed")
        self.live_feed_toggle.setObjectName("ghostButton")
        self.live_feed_toggle.setCheckable(True)
        self.live_feed_toggle.setChecked(False)
        self.live_feed_toggle.clicked.connect(self._toggle_live_feed)
        self.live_feed = QPlainTextEdit()
        self.live_feed.setReadOnly(True)
        self.live_feed.setObjectName("console")
        self.live_feed.setMaximumBlockCount(200)
        self.live_feed.setVisible(False)
        table_card.content_layout.addWidget(self.live_feed_toggle)
        table_card.content_layout.addWidget(self.live_feed)
        table_card.content_layout.addWidget(self.table)
        layout.addWidget(table_card, 1)
        return widget

    def build_diagnostics_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        title = QLabel("Diagnostics")
        title.setObjectName("pageTitle")
        layout.addWidget(title)

        controls_card = Card("Targets & Options")
        controls_layout = controls_card.content_layout

        target_row = QHBoxLayout()
        target_row.setSpacing(10)
        target_row.addWidget(QLabel("Target:"))
        self.diag_target_input = QLineEdit()
        self.diag_target_input.setPlaceholderText("example.com or 8.8.8.8")
        target_row.addWidget(self.diag_target_input)
        controls_layout.addLayout(target_row)

        options_row = QHBoxLayout()
        options_row.setSpacing(12)
        options_row.addWidget(QLabel("Ping count:"))
        self.diag_ping_count = QSpinBox()
        self.diag_ping_count.setRange(1, 200)
        self.diag_ping_count.setValue(4)
        options_row.addWidget(self.diag_ping_count)

        options_row.addWidget(QLabel("Timeout (ms):"))
        self.diag_timeout = QSpinBox()
        self.diag_timeout.setRange(200, 5000)
        self.diag_timeout.setValue(1000)
        options_row.addWidget(self.diag_timeout)

        options_row.addWidget(QLabel("Traceroute max hops:"))
        self.diag_max_hops = QSpinBox()
        self.diag_max_hops.setRange(1, 64)
        self.diag_max_hops.setValue(30)
        options_row.addWidget(self.diag_max_hops)
        options_row.addStretch(1)
        controls_layout.addLayout(options_row)

        buttons_row = QHBoxLayout()
        buttons_row.setSpacing(10)
        self.btn_diag_ping = QPushButton("Ping")
        self.btn_diag_traceroute = QPushButton("Traceroute")
        self.btn_diag_stop = QPushButton("Stop")
        self.btn_diag_stop.setEnabled(False)
        buttons_row.addWidget(self.btn_diag_ping)
        buttons_row.addWidget(self.btn_diag_traceroute)
        buttons_row.addWidget(self.btn_diag_stop)
        buttons_row.addStretch(1)
        controls_layout.addLayout(buttons_row)
        layout.addWidget(controls_card)

        output_card = Card("Output")
        self.diag_output = QPlainTextEdit()
        self.diag_output.setObjectName("console")
        self.diag_output.setReadOnly(True)
        self.diag_output.setMinimumHeight(250)
        context_row = QHBoxLayout()
        context_row.setSpacing(12)
        tool_label = QLabel("Tool:")
        tool_label.setObjectName("keyLabel")
        self.diag_tool_value = QLabel("-")
        self.diag_tool_value.setObjectName("valueLabel")
        target_label = QLabel("Target:")
        target_label.setObjectName("keyLabel")
        self.diag_target_value = QLabel("-")
        self.diag_target_value.setObjectName("valueLabel")
        self.diag_running_badge = QLabel()
        set_badge(self.diag_running_badge, "gray", "Idle", size="sm")
        context_row.addWidget(tool_label)
        context_row.addWidget(self.diag_tool_value)
        context_row.addSpacing(10)
        context_row.addWidget(target_label)
        context_row.addWidget(self.diag_target_value)
        context_row.addStretch(1)
        context_row.addWidget(self.diag_running_badge)
        output_card.content_layout.addLayout(context_row)
        output_card.content_layout.addWidget(self.diag_output)

        status_row = QHBoxLayout()
        status_row.addWidget(QLabel("Status:"))
        self.diag_status_lbl = QLabel()
        set_badge(self.diag_status_lbl, "gray", "Idle")
        status_row.addWidget(self.diag_status_lbl)
        status_row.addStretch(1)
        output_card.content_layout.addLayout(status_row)
        layout.addWidget(output_card, 1)
        return widget

    def build_av_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        title = QLabel("AV / Multicast Insights")
        title.setObjectName("pageTitle")
        layout.addWidget(title)

        header_card = Card("Interface")
        header_row = QHBoxLayout()
        header_row.setSpacing(8)
        self.av_iface_lbl = QLabel("Interface: Unknown")
        self.av_iface_lbl.setObjectName("valueLabel")
        header_row.addWidget(self.av_iface_lbl)
        header_row.addStretch(1)
        self.btn_av_refresh = QPushButton("Refresh")
        header_row.addWidget(self.btn_av_refresh)
        header_card.content_layout.addLayout(header_row)
        layout.addWidget(header_card)

        insights_card = Card("Insights")
        self.av_status_labels: Dict[str, QLabel] = {}
        grid = QGridLayout()
        grid.setSpacing(12)
        subtitle = QLabel("Real-time Multicast Indicators")
        subtitle.setObjectName("sectionTitle")
        insights_card.content_layout.addWidget(subtitle)
        metrics = [
            ("Multicast Traffic", "multicast"),
            ("IGMP Activity", "igmp"),
            ("IGMP Querier", "igmp_querier"),
            ("PTP (IEEE 1588)", "ptp"),
            ("Dante", "dante"),
            ("NVX / Video", "nvx"),
        ]
        for idx, (title_text, key) in enumerate(metrics):
            tile = QWidget()
            tile.setObjectName("metricTile")
            tile_layout = QVBoxLayout(tile)
            tile_layout.setContentsMargins(12, 12, 12, 12)
            tile_layout.setSpacing(8)
            tile.setMinimumHeight(120)
            t_lbl = QLabel(title_text)
            t_lbl.setObjectName("tileTitle")
            badge_lbl = QLabel()
            badge_lbl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            set_badge(badge_lbl, "gray", "Unknown")
            self.av_status_labels[key] = badge_lbl
            tile_layout.addWidget(t_lbl)
            badge_row = QHBoxLayout()
            badge_row.addWidget(badge_lbl)
            badge_row.addStretch(1)
            tile_layout.addLayout(badge_row)
            tile_layout.addStretch(1)
            grid.addWidget(tile, idx // 3, idx % 3)
        insights_card.content_layout.addLayout(grid)
        layout.addWidget(insights_card)

        evidence_card = Card("Evidence")
        self.av_evidence = QPlainTextEdit()
        self.av_evidence.setObjectName("console")
        self.av_evidence.setReadOnly(True)
        self.av_evidence.setMaximumBlockCount(30)
        self.av_evidence.setMinimumHeight(200)
        evidence_card.content_layout.addWidget(self.av_evidence)
        evidence_btn_row = QHBoxLayout()
        evidence_btn_row.addStretch(1)
        self.btn_av_copy = QPushButton("Copy")
        self.btn_av_copy.setObjectName("secondaryButton")
        evidence_btn_row.addWidget(self.btn_av_copy)
        self.btn_av_clear = QPushButton("Clear")
        evidence_btn_row.addWidget(self.btn_av_clear)
        evidence_card.content_layout.addLayout(evidence_btn_row)
        layout.addWidget(evidence_card, 1)

        self.btn_av_refresh.clicked.connect(self.refresh_av_insights)
        self.btn_av_clear.clicked.connect(self.clear_av_evidence)
        self.btn_av_copy.clicked.connect(self.copy_av_evidence)
        return widget

    def update_diag_status(self, text: str, state: str = "gray"):
        set_badge(self.diag_status_lbl, state, text)

    def _set_diag_context(self, tool: str, target: str):
        self.diag_tool_value.setText(tool or "-")
        self.diag_target_value.setText(target or "-")

    def start_diag_worker(self, command: List[str], pre_status: str):
        if self.diag_worker and self.diag_worker.isRunning():
            return
        self.diag_output.clear()
        self.update_diag_status(pre_status, "yellow")
        self.diag_worker = DiagnosticsWorker(command)
        self.diag_worker.diagOutputLine.connect(self.on_diag_output_line)
        self.diag_worker.diagStatusChanged.connect(self.on_diag_status_changed)
        self.diag_worker.diagRunningChanged.connect(self.on_diag_running_changed)
        self.diag_worker.finished.connect(self.on_diag_finished)
        self.diag_worker.start()

    def run_diag_ping(self):
        target = self.diag_target_input.text().strip()
        if not target:
            self.update_diag_status("Failed: Target required", "red")
            return
        self._set_diag_context("Ping", target)
        cmd = [
            "ping",
            "-n",
            str(self.diag_ping_count.value()),
            "-w",
            str(self.diag_timeout.value()),
            target,
        ]
        self.start_diag_worker(cmd, f"Running ping to {target}...")

    def run_diag_traceroute(self):
        target = self.diag_target_input.text().strip()
        if not target:
            self.update_diag_status("Failed: Target required", "red")
            return
        self._set_diag_context("Traceroute", target)
        cmd = [
            "tracert",
            "-h",
            str(self.diag_max_hops.value()),
            target,
        ]
        self.start_diag_worker(cmd, f"Running traceroute to {target}...")

    def stop_diag_worker(self):
        if self.diag_worker:
            self.diag_worker.stop()

    @Slot(str)
    def on_diag_output_line(self, line: str):
        self.diag_output.appendPlainText(line)

    @Slot(str)
    def on_diag_status_changed(self, status: str):
        state = "green" if status.lower().startswith("completed") else "yellow"
        if status.lower().startswith("failed"):
            state = "red"
        self.update_diag_status(status, state)

    @Slot(bool)
    def on_diag_running_changed(self, running: bool):
        self.btn_diag_ping.setEnabled(not running)
        self.btn_diag_traceroute.setEnabled(not running)
        self.btn_diag_stop.setEnabled(running)
        if running:
            set_badge(self.diag_running_badge, "blue", "Running", size="sm")
        else:
            set_badge(self.diag_running_badge, "gray", "Idle", size="sm")

    def on_diag_finished(self):
        self.diag_worker = None

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
        self.external_ip_lbl.setText(ip or "Unavailable")

    @Slot(bool)
    def set_connectivity_state(self, online: bool):
        state = "green" if online else "red"
        text = "Online" if online else "Offline"
        set_badge(self.connectivity_lbl, state, text, size="lg")
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

    def _style_status(self, lbl: QLabel, prefix: str, status: str, color_map: Dict[str, str], badge_size: str = "lg"):
        badge_state = color_map.get(status.lower(), "gray")
        set_badge(lbl, badge_state, f"{prefix}: {status}", size=badge_size)

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
        if not iface_name or sniff is None or IP is None:
            return None
        try:
            packets = sniff(filter="igmp", iface=iface_name, timeout=2, store=True, count=5)
            for pkt in packets:
                try:
                    if pkt.haslayer(IP) and getattr(pkt[IP], "proto", None) == 2:
                        return True
                except Exception:
                    continue
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
            color_map = {"likely": "green", "unknown": "yellow", "unlikely": "red"}
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
            color_map_basic = {"installed": "green", "not installed": "red", "unknown": "yellow"}
            color_map_admin = {"admin": "green", "not admin": "red", "unknown": "yellow"}
            color_map_arp = {
                "available": "green",
                "limited/unavailable": "red",
                "unknown": "yellow",
            }
            self._style_status(self.npcap_status_lbl, "Npcap Installed", payload.get("npcap", "Unknown"), color_map_basic, "sm")
            self._style_status(self.admin_status_lbl, "Running as Administrator", payload.get("admin", "Unknown"), color_map_admin, "sm")
            self._style_status(self.arp_status_lbl, "ARP Available", payload.get("arp", "Unknown"), color_map_arp, "sm")
        finally:
            self.env_check_running = False

    def run_l2_check(self):
        if self.l2_check_running:
            return
        data = self.if_combo.currentData()
        iface_name = data.get("name") if isinstance(data, dict) else None
        if not iface_name:
            self._update_l2_ui({"lldp": {"status": "Unknown"}, "vlans": {"status": "Unknown", "vlans": []}})
            return

        self.l2_check_running = True
        self.l2_worker = Layer2InfoWorker(iface_name)
        self.l2_worker.result.connect(self.apply_l2_result)
        self.l2_worker.finished.connect(self.on_l2_finished)
        self.l2_worker.start()

    @Slot(dict)
    def apply_l2_result(self, payload: dict):
        self._update_l2_ui(payload)

    def _update_l2_ui(self, payload: dict):
        lldp = payload.get("lldp", {}) if payload else {}
        vlans = payload.get("vlans", {}) if payload else {}
        meta = payload.get("meta", {}) if payload else {}
        lldp_status = str(lldp.get("status", "Unknown"))
        color_map = {"detected": "green", "not detected": "red", "unknown": "yellow"}
        self._style_status(self.lldp_status_lbl, "LLDP", lldp_status, color_map)

        def set_or_dash(lbl: QLabel, value: Optional[str]):
            lbl.setText(value if value else "-")

        set_or_dash(self.lldp_chassis_lbl, lldp.get("chassis_id"))
        set_or_dash(self.lldp_port_lbl, lldp.get("port_id"))
        set_or_dash(self.lldp_sysname_lbl, lldp.get("system_name"))
        set_or_dash(self.lldp_portdesc_lbl, lldp.get("port_description"))
        set_or_dash(self.lldp_mgmt_lbl, lldp.get("management_address"))

        vlan_status = str(vlans.get("status", "Unknown"))
        vlan_ids = vlans.get("vlans") or []
        vlan_state_map = {"detected": "green", "none detected": "yellow", "unknown": "yellow"}
        badge_state = vlan_state_map.get(vlan_status.lower(), "gray")
        set_badge(self.vlan_status_badge, badge_state, f"VLANs: {vlan_status}")
        if vlan_status.lower() == "detected" and vlan_ids:
            self.vlan_lbl.setText(", ".join(str(v) for v in vlan_ids))
        else:
            self.vlan_lbl.setText(vlan_status)

        iface_text = str(meta.get("iface", "-")) if meta else "-"
        captured = meta.get("captured", 0) if meta else 0
        lldp_frames = meta.get("lldp_frames", 0) if meta else 0
        vlan_frames = meta.get("vlan_frames", 0) if meta else 0
        error_text = meta.get("error") if meta else None

        self.l2_iface_hint.setText(f"Capture interface: {iface_text}")
        if error_text:
            self.l2_capture_hint.setText("Captured frames: Unknown (capture failed)")
        else:
            self.l2_capture_hint.setText(f"Captured frames: {captured}")
        self.l2_counts_hint.setText(
            f"LLDP frames: {lldp_frames} | VLAN-tagged frames: {vlan_frames}"
        )

    def on_l2_finished(self):
        self.l2_check_running = False

    def refresh_av_insights(self, auto_trigger: bool = False):
        if self.av_check_running:
            return
        data = self.if_combo.currentData()
        iface_name = data.get("name") if isinstance(data, dict) else None
        if not iface_name:
            self.apply_av_insights({})
            return

        if not auto_trigger:
            self.clear_av_evidence()

        self.av_check_running = True
        self.av_worker = AVInsightsWorker(iface_name)
        self.av_worker.avInsightsUpdated.connect(self.apply_av_insights)
        self.av_worker.avEvidenceLine.connect(self.append_av_evidence)
        self.av_worker.finished.connect(self.on_av_finished)
        self.av_worker.start()

    @Slot(dict)
    def apply_av_insights(self, payload: dict):
        default_status = "Unknown"
        color_map = {
            "present": "green",
            "seen": "green",
            "likely": "green",
            "possible": "yellow",
            "not seen": "red",
            "not detected": "red",
            "none": "red",
            "unknown": "yellow",
        }
        for key, lbl in self.av_status_labels.items():
            status = str(payload.get(key, default_status)) if payload else default_status
            styled = f"{status} (best-effort)"
            badge_state = color_map.get(status.lower(), "gray")
            set_badge(lbl, badge_state, styled)

    @Slot(str)
    def append_av_evidence(self, line: str):
        if line:
            self.av_evidence.appendPlainText(line)

    def clear_av_evidence(self):
        self.av_evidence.clear()

    def copy_av_evidence(self):
        QApplication.clipboard().setText(self.av_evidence.toPlainText())

    def on_av_finished(self):
        self.av_check_running = False

    def on_interface_changed(self, index: int):
        self.refresh_network_info(force=True)


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

    def _sync_interface_list(self, active_ifaces: List[dict], preferred_name: Optional[str]) -> Tuple[Optional[str], Optional[dict]]:
        existing_entries = []
        for i in range(self.if_combo.count()):
            data = self.if_combo.itemData(i)
            if isinstance(data, dict):
                existing_entries.append((data.get("name"), data.get("ip"), data.get("cidr")))

        new_entries = [(it.get("name"), it.get("ip"), it.get("cidr")) for it in active_ifaces]
        new_names = [it.get("name") for it in active_ifaces]
        needs_reload = existing_entries != new_entries
        target_name = preferred_name if preferred_name in new_names else new_names[0] if new_names else None

        if needs_reload:
            self.if_combo.blockSignals(True)
            self.if_combo.clear()
            for it in active_ifaces:
                label = f"{it['name']}  |  {it['ip']}  |  {it['cidr']}"
                self.if_combo.addItem(label, it)
            if target_name and target_name in new_names:
                self.if_combo.setCurrentIndex(new_names.index(target_name))
            self.if_combo.blockSignals(False)

        data = self.if_combo.currentData()
        iface_name = data.get("name") if isinstance(data, dict) else target_name
        iface_data = next((it for it in active_ifaces if it.get("name") == iface_name), None)
        if iface_data is None and active_ifaces:
            iface_data = active_ifaces[0]
            iface_name = iface_data.get("name")
            if needs_reload:
                self.if_combo.blockSignals(True)
                self.if_combo.setCurrentIndex(0)
                self.if_combo.blockSignals(False)
        return iface_name, iface_data

    def _apply_dhcp_info(self, info: Dict[str, str], unavailable: bool = False):
        fallback = "Unavailable" if unavailable else "N/A"
        for key, lbl in self.dhcp_value_labels.items():
            lbl.setText(info.get(key, "") or fallback)
        self.client_ip_lbl.setText(info.get("ip", "") or fallback)
        self.interface_lbl.setText(info.get("interface", "") or fallback)

    def _set_l2_refreshing_state(self):
        set_badge(self.lldp_status_lbl, "yellow", "LLDP: Refreshing...")
        set_badge(self.vlan_status_badge, "yellow", "VLANs: Refreshing...")
        for lbl in [
            self.lldp_chassis_lbl,
            self.lldp_port_lbl,
            self.lldp_sysname_lbl,
            self.lldp_portdesc_lbl,
            self.lldp_mgmt_lbl,
            self.vlan_lbl,
        ]:
            lbl.setText("Refreshing...")

    def _update_network_updated_label(self):
        if not getattr(self, "network_updated_lbl", None):
            return
        if not self.network_last_updated_ts:
            self.network_updated_lbl.setText("Last updated: -")
            return
        diff = int(time.time() - self.network_last_updated_ts)
        if diff <= 1:
            text = "Last updated: just now"
        elif diff < 60:
            text = f"Last updated: {diff}s ago"
        else:
            minutes = diff // 60
            text = f"Last updated: {minutes}m ago"
        self.network_updated_lbl.setText(text)

    def _set_network_refreshing_state(self):
        self.external_ip_lbl.setText("Updating...")
        self.client_ip_lbl.setText("Updating...")
        self.interface_lbl.setText("Updating...")
        set_badge(self.connectivity_lbl, "yellow", "Checking...", size="lg")
        for lbl in self.dhcp_value_labels.values():
            lbl.setText("Updating...")
        self._set_l2_refreshing_state()

    def _set_network_unavailable_state(self):
        self.network_last_updated_ts = None
        self._update_network_updated_label()
        self.external_ip_lbl.setText("Unavailable")
        self.client_ip_lbl.setText("Unavailable")
        self.interface_lbl.setText("Unavailable")
        set_badge(self.connectivity_lbl, "red", "Offline", size="lg")
        self._apply_dhcp_info({}, unavailable=True)
        set_badge(self.lldp_status_lbl, "gray", "LLDP: Unavailable")
        set_badge(self.vlan_status_badge, "gray", "VLANs: Unavailable")
        for lbl in [
            self.lldp_chassis_lbl,
            self.lldp_port_lbl,
            self.lldp_sysname_lbl,
            self.lldp_portdesc_lbl,
            self.lldp_mgmt_lbl,
            self.vlan_lbl,
        ]:
            lbl.setText("Unavailable")

    def toggle_l2_debug(self):
        visible = not self.l2_debug_container.isVisible()
        self.l2_debug_container.setVisible(visible)
        self.l2_toggle_btn.setText("Hide capture details" if visible else "Show capture details")

    def refresh_network_info(self, force: bool = False):
        active_ifaces = get_active_ipv4_interfaces()
        preferred_data = self.if_combo.currentData()
        preferred_name = preferred_data.get("name") if isinstance(preferred_data, dict) else None

        if not active_ifaces:
            if force or self.last_network_snapshot:
                self.last_network_snapshot = {}
                self.if_combo.blockSignals(True)
                self.if_combo.clear()
                self.if_combo.addItem("No active IPv4 interfaces found", None)
                self.if_combo.blockSignals(False)
                self.btn_scan.setEnabled(False)
                self._set_network_unavailable_state()
            return

        self.btn_scan.setEnabled(True)

        iface_name, iface_data = self._sync_interface_list(active_ifaces, preferred_name)
        if not iface_name or not iface_data:
            return

        dhcp_info = get_dhcp_info(iface_name, iface_data)
        dhcp_info.setdefault("interface", iface_name)
        dhcp_info.setdefault("ip", iface_data.get("ip", ""))

        snapshot = {
            "interface": iface_name,
            "ip": dhcp_info.get("ip", ""),
            "gateway": dhcp_info.get("gateway", ""),
            "dhcp_server": dhcp_info.get("dhcp_server", ""),
        }

        if not force and snapshot == self.last_network_snapshot:
            self.network_last_updated_ts = time.time()
            self._update_network_updated_label()
            return

        self.last_network_snapshot = snapshot
        self._set_network_refreshing_state()
        self._apply_dhcp_info(dhcp_info)
        self.av_iface_lbl.setText(f"Interface: {iface_name}")
        self.network_last_updated_ts = time.time()
        self._update_network_updated_label()

        self.fetch_external_ip()
        self.check_connectivity()
        self.run_env_checks()
        self.run_igmp_check()
        self.refresh_av_insights(auto_trigger=True)
        self.run_l2_check()

    def _set_table_item(self, row: int, col: int, text: str, align: Qt.AlignmentFlag):
        item = self.table.item(row, col)
        if item is None:
            item = QTableWidgetItem(text)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            item.setTextAlignment(align)
            self.table.setItem(row, col, item)
        else:
            if item.text() != text:
                item.setText(text)
            if item.textAlignment() != align:
                item.setTextAlignment(align)

    def _compute_identity_key(self, d: Device) -> str:
        if is_valid_mac(d.mac):
            return d.mac.replace("-", ":").lower()
        if d.hostname:
            return d.hostname.lower()
        return d.ip

    def _merge_identity(self, incoming: Device) -> Device:
        incoming.last_seen_ts = time.time()
        key = self._compute_identity_key(incoming)
        existing_key = self.ip_to_key.get(incoming.ip)
        if existing_key and existing_key != key and is_valid_mac(incoming.mac):
            key = incoming.mac.replace("-", ":").lower()

        target = self.devices_by_key.get(key)
        if target is None:
            target = incoming
            target.primary_key = key
            target.ips_seen.add(incoming.ip)
            self.devices_by_key[key] = target
        else:
            target.primary_key = key
            target.last_seen_ts = incoming.last_seen_ts
            target.ips_seen.add(incoming.ip)
            if incoming.ip != target.ip:
                target.ip = incoming.ip
            if incoming.mac and not target.mac:
                target.mac = incoming.mac
            if incoming.vendor and not target.vendor:
                target.vendor = incoming.vendor
            if incoming.hostname and not target.hostname:
                target.hostname = incoming.hostname
            if incoming.rtt_ms is not None:
                target.rtt_ms = incoming.rtt_ms
            target.protocols.update(incoming.protocols)
            target.sources.update(incoming.sources)
            if incoming.description:
                target.description = normalize_description(target.description, incoming.description)
            target.mdns_names.update(incoming.mdns_names)
            if incoming.ssdp_server and not target.ssdp_server:
                target.ssdp_server = incoming.ssdp_server
            if incoming.ssdp_st and not target.ssdp_st:
                target.ssdp_st = incoming.ssdp_st
            if incoming.ssdp_usn and not target.ssdp_usn:
                target.ssdp_usn = incoming.ssdp_usn
            if incoming.ssdp_location and not target.ssdp_location:
                target.ssdp_location = incoming.ssdp_location

        self.ip_to_key[incoming.ip] = key
        for ip in target.ips_seen:
            self.ip_to_key[ip] = key
        self.devices_map[incoming.ip] = target
        return target

    def _presence_state(self, d: Device) -> str:
        now = time.time()
        online_ttl = int(self.sp_online_ttl.value()) if hasattr(self, "sp_online_ttl") else self.ONLINE_TTL_SEC
        stale_ttl = int(self.sp_stale_ttl.value()) if hasattr(self, "sp_stale_ttl") else self.STALE_TTL_SEC
        offline_ttl = int(self.sp_offline_ttl.value()) if hasattr(self, "sp_offline_ttl") else self.OFFLINE_AFTER_SEC
        delta = now - d.last_seen_ts
        if delta <= online_ttl:
            return "Online"
        if delta <= stale_ttl:
            return "Unknown"
        if delta <= offline_ttl:
            return "Offline"
        return "Offline"

    def _style_presence_item(self, item: QTableWidgetItem, state: str):
        colors = {
            "online": (Qt.darkGreen, Qt.white),
            "unknown": (Qt.darkYellow, Qt.black),
            "offline": (Qt.red, Qt.white),
        }
        fg, bg = colors.get(state.lower(), (Qt.black, Qt.white))
        item.setForeground(fg)
        item.setBackground(bg)

    def _toggle_live_feed(self):
        visible = self.live_feed_toggle.isChecked()
        self.live_feed.setVisible(visible)
        self.live_feed_toggle.setText("Hide Live Feed" if visible else "Show Live Feed")

    def _append_feed(self, text: str):
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] {text}"
        self.live_feed_lines.append(line)
        self.live_feed_lines = self.live_feed_lines[-200:]
        if self.live_feed.isVisible():
            self.live_feed.setPlainText("\n".join(self.live_feed_lines))
            self.live_feed.verticalScrollBar().setValue(self.live_feed.verticalScrollBar().maximum())

    def _tick_presence(self):
        changed: List[Device] = []
        for key, dev in self.devices_by_key.items():
            prev = self._last_presence_state.get(key)
            state = self._presence_state(dev)
            if prev and prev != state:
                self._append_feed(f"STATE {dev.ip} -> {state}")
            self._last_presence_state[key] = state
            if state != prev:
                changed.append(dev)
        for dev in changed:
            self.upsert_device_row(dev)
        if changed:
            self._update_status_counts()

    def upsert_device_row(self, d: Device):
        if d.mac and not d.vendor:
            d.vendor = vendor_from_mac(d.mac, self.oui_map)

        key = d.primary_key or self._compute_identity_key(d)
        d.primary_key = key
        row = self._row_by_key.get(key)
        if row is None:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self._row_by_key[key] = row

        left_align = Qt.AlignLeft | Qt.AlignVCenter
        right_align = Qt.AlignRight | Qt.AlignVCenter

        ip_list = sorted(d.ips_seen) if d.ips_seen else [d.ip]
        extra = max(0, len(ip_list) - 1)
        ips_label = d.ip if not extra else f"{d.ip} (+{extra})"
        self._set_table_item(row, 0, d.ip, left_align)
        item_ips = self.table.item(row, 1)
        if item_ips is None:
            item_ips = QTableWidgetItem(ips_label)
            item_ips.setFlags(item_ips.flags() & ~Qt.ItemIsEditable)
            item_ips.setToolTip("\n".join(ip_list))
            self.table.setItem(row, 1, item_ips)
        else:
            item_ips.setText(ips_label)
            item_ips.setToolTip("\n".join(ip_list))

        presence_state = self._presence_state(d)
        presence_item = self.table.item(row, 2)
        if presence_item is None:
            presence_item = QTableWidgetItem(presence_state)
            presence_item.setFlags(presence_item.flags() & ~Qt.ItemIsEditable)
            presence_item.setTextAlignment(left_align)
            self.table.setItem(row, 2, presence_item)
        else:
            presence_item.setText(presence_state)
        self._style_presence_item(presence_item, presence_state)

        self._set_table_item(row, 3, d.mac or "", left_align)
        self._set_table_item(row, 4, d.vendor or "", left_align)
        self._set_table_item(row, 5, d.hostname or "", left_align)
        self._set_table_item(
            row,
            6,
            "" if d.rtt_ms is None else f"{d.rtt_ms:.2f}",
            right_align,
        )
        found_by = d.sources or d.protocols
        self._set_table_item(row, 7, "|".join(sorted(found_by)), left_align)
        self._set_table_item(row, 8, "|".join(sorted(d.protocols)), left_align)
        self._set_table_item(row, 9, d.description or "", left_align)

        hide = self.cb_online_only.isChecked() and presence_state != "Online"
        self.table.setRowHidden(row, hide)

    def _remove_device_row(self, key: str):
        row = self._row_by_key.pop(key, None)
        if row is None:
            return
        self.table.removeRow(row)
        for other_key, other_row in list(self._row_by_key.items()):
            if other_row > row:
                self._row_by_key[other_key] = other_row - 1

    @Slot(object)
    def on_device_found(self, device: Device):
        merged = self._merge_identity(device)
        self._pending_updates[merged.primary_key or merged.ip] = merged

    def flush_pending_updates(self):
        if not self._pending_updates:
            return
        updates = list(self._pending_updates.values())
        self._pending_updates.clear()
        for dev in updates:
            self.upsert_device_row(dev)
        self._update_status_counts()
        if not updates:
            for dev in self.devices_by_key.values():
                key = dev.primary_key or dev.ip
                row = self._row_by_key.get(key)
                if row is not None:
                    hide = self.cb_online_only.isChecked() and self._presence_state(dev) != "Online"
                    self.table.setRowHidden(row, hide)

    def _update_status_counts(self):
        online = unknown = offline = 0
        for dev in self.devices_by_key.values():
            state = self._presence_state(dev)
            if state == "Online":
                online += 1
            elif state == "Unknown":
                unknown += 1
            else:
                offline += 1
        total = len(self.devices_by_key)
        self.presence_summary_lbl.setText(
            f"Online: {online} | Unknown: {unknown} | Offline: {offline} | Total known: {total}"
        )
        if self.worker and self.worker.isRunning():
            self.status_lbl.setText(f"Scanning... Found {total} devices (online: {online}).")
        else:
            self.status_lbl.setText(f"Done. Found {total} devices (online: {online}).")

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

        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.devices = []
        self.devices_map = {}
        self.devices_by_key = {}
        self.ip_to_key = {}
        self._row_by_key = {}
        self._pending_updates = {}
        self._last_presence_state = {}
        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.status_lbl.setText(f"Starting scan on {cidr_label} ...")
        self.progress_lbl.setText("Initializing...")

        self.worker = ScanWorker(
            cidrs=cidrs,
            cidr_label=cidr_label,
            iface_name=it["name"],
            do_ping=self.cb_ping.isChecked(),
            do_mdns=self.cb_mdns.isChecked(),
            do_ssdp=self.cb_ssdp.isChecked(),
            do_rdns=self.cb_rdns.isChecked(),
            fetch_upnp_xml=(self.cb_ssdp.isChecked() and self.cb_upnp_xml.isChecked()),
            mdns_duration_s=int(self.sp_mdns.value()),
            ssdp_timeout_s=int(self.sp_ssdp.value()),
            arp_timeout=float(self.sp_arp_timeout.value()),
            arp_retries=int(self.sp_arp_retries.value()),
            icmp_timeout=float(self.sp_icmp_timeout.value()),
            icmp_retries=int(self.sp_icmp_retries.value()),
            tcp_timeout=float(self.sp_tcp_timeout.value()),
            concurrency=int(self.sp_concurrency.value()),
            oui_map=self.oui_map,
        )
        self.worker.status.connect(self.status_lbl.setText)
        self.worker.result.connect(self.on_scan_finished)
        self.worker.device_found.connect(self.on_device_found)
        self.worker.partial.connect(self.on_partial_results)
        self.worker.progress_update.connect(self.on_scan_progress)
        self.worker.scan_started.connect(self.on_scan_started)
        self.worker.finished_ok.connect(self.on_finished)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.start()
        self._stop_continuous_worker()

    def stop_scan(self):
        if self.worker:
            self.worker.stop()
        self.btn_stop.setEnabled(False)
        self.btn_scan.setEnabled(True)
        self.progress_lbl.setText("Stopping...")

    def on_finished(self):
        self.btn_stop.setEnabled(False)
        self.btn_scan.setEnabled(True)
        self._update_status_counts()
        if self.cb_continuous.isChecked():
            self._start_continuous_worker()

    def _start_continuous_worker(self):
        if self.worker and self.worker.isRunning():
            return
        if self.continuous_worker and self.continuous_worker.isRunning():
            return
        cidrs: List[ipaddress.IPv4Network] = []
        data = self.if_combo.currentData()
        if isinstance(data, dict) and data.get("cidr"):
            try:
                cidrs.append(ipaddress.IPv4Network(data["cidr"], strict=False))
            except Exception:
                pass
        known_ips = [dev.ip for dev in self.devices_by_key.values()]
        self.continuous_worker = BackgroundDiscoveryWorker(cidrs, known_ips)
        self.continuous_worker.device_found.connect(self.on_device_found)
        self.continuous_worker.start()

    def _stop_continuous_worker(self):
        if self.continuous_worker:
            self.continuous_worker.stop()
            self.continuous_worker.wait(500)
            self.continuous_worker = None

    def on_continuous_changed(self, state: int):
        if state:
            self._start_continuous_worker()
        else:
            self._stop_continuous_worker()

    def on_worker_finished(self):
        self.flush_pending_updates()
        self.table.setSortingEnabled(True)

    @Slot(int, str)
    def on_scan_started(self, total: int, cidr_label: str):
        self.progress_lbl.setText(f"Scanning {cidr_label} ({total} targets)...")

    @Slot(list)
    def on_scan_batch_update(self, devices: List[Device]):
        for d in devices:
            self.devices_map[d.ip] = d
            self.upsert_device_row(d)

    @Slot(list)
    def on_partial_results(self, devices: List[Device]):
        for d in devices:
            merged = self._merge_identity(d)
            self._pending_updates[merged.primary_key or merged.ip] = merged
        self.flush_pending_updates()

    @Slot(int, int, str)
    def on_scan_progress(self, done: int, total: int, phase: str):
        found = len(self.devices_map)
        online = len(self._row_by_key)
        pct = int((done / total) * 100) if total else 0
        pct = min(max(pct, 0), 100)
        self.progress_lbl.setText(
            f"Scanning: {done}/{total} ({pct}%) | Phase: {phase} | Found: {found} (online: {online})"
        )

    @Slot(list)
    def on_scan_finished(self, devices: list):
        for d in devices:
            if d.mac and not d.vendor:
                d.vendor = vendor_from_mac(d.mac, self.oui_map)
            merged = self._merge_identity(d)
            self._pending_updates[merged.primary_key or merged.ip] = merged

        self.flush_pending_updates()
        self.table.setSortingEnabled(True)
        self.table.sortItems(0, Qt.AscendingOrder)
        self.progress_lbl.setText(
            f"Completed. Found {len(self.devices_by_key)} devices."
        )
        self._update_status_counts()

    def export_csv(self):
        export_list = list(self.devices_by_key.values()) if self.devices_by_key else (self.devices if self.devices else list(self.devices_map.values()))
        if not export_list:
            self.status_lbl.setText("Nothing to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "devices.csv", "CSV Files (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([
                "IP",
                "IPs_Seen",
                "MAC",
                "Vendor",
                "Hostname",
                "Ping_ms",
                "Found_By",
                "Protocols",
                "Description",
            ])
            for d in export_list:
                ips_seen = ",".join(sorted(d.ips_seen)) if getattr(d, "ips_seen", None) else d.ip
                w.writerow([
                    d.ip,
                    ips_seen,
                    d.mac or "",
                    d.vendor or "",
                    d.hostname or "",
                    "" if d.rtt_ms is None else f"{d.rtt_ms:.2f}",
                    "|".join(sorted(d.sources or d.protocols)),
                    "|".join(sorted(d.protocols)),
                    d.description or "",
                ])

        self.status_lbl.setText(f"Exported: {path}")

    def closeEvent(self, event):  # type: ignore[override]
        for timer in [
            getattr(self, "connectivity_timer", None),
            getattr(self, "igmp_timer", None),
            getattr(self, "env_timer", None),
            getattr(self, "network_monitor_timer", None),
            getattr(self, "network_timestamp_timer", None),
            getattr(self, "_update_timer", None),
            getattr(self, "presence_timer", None),
        ]:
            if timer:
                timer.stop()

        if self.worker:
            self.worker.stop()
            if self.worker.isRunning():
                self.worker.wait(1000)

        if self.diag_worker:
            self.diag_worker.stop()
            if self.diag_worker.isRunning():
                self.diag_worker.wait(1000)

        for thread in [self.l2_worker, self.av_worker]:
            if thread and thread.isRunning():
                thread.requestInterruption()
                thread.wait(1000)

        self._stop_continuous_worker()

        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
