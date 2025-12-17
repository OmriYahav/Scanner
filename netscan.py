import sys
import os
import csv
import time
import webbrowser
import socket
import asyncio
import ipaddress
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional, Set, List, Dict, Tuple

import psutil
import requests
from ping3 import ping

from scapy.all import ARP, Ether, srp, conf  # type: ignore

from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange  # type: ignore

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QComboBox, QTableWidget, QTableWidgetItem,
    QFileDialog, QCheckBox, QSpinBox, QMessageBox
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


def ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        return ipaddress.IPv4Address(ip) in net
    except Exception:
        return False


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
        cidr: str,
        iface_name: Optional[str],
        do_ping: bool,
        do_mdns: bool,
        do_ssdp: bool,
        do_rdns: bool,
        fetch_upnp_xml: bool,
        mdns_duration_s: int,
        ssdp_timeout_s: int,
        do_port_scan: bool,
        port_start: int,
        port_end: int,
        port_timeout_ms: int,
        port_concurrency: int,
        parent=None
    ):
        super().__init__(parent)
        self.cidr = cidr
        self.iface_name = iface_name
        self.do_ping = do_ping
        self.do_mdns = do_mdns
        self.do_ssdp = do_ssdp
        self.do_rdns = do_rdns
        self.fetch_upnp_xml = fetch_upnp_xml
        self.mdns_duration_s = mdns_duration_s
        self.ssdp_timeout_s = ssdp_timeout_s
        self.do_port_scan = do_port_scan
        self.port_start = port_start
        self.port_end = port_end
        self.port_timeout_ms = port_timeout_ms
        self.port_concurrency = max(1, port_concurrency)
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

    async def _probe_port(self, ip: str, port: int, timeout_s: float) -> bool:
        if self._stop:
            return False
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout_s)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except asyncio.TimeoutError:
            return False
        except (OSError, asyncio.CancelledError):
            return False

    async def _scan_ports_async(
        self,
        ips: List[str],
        ports: List[int],
        timeout_s: float,
        max_concurrency: int,
    ) -> Dict[str, List[int]]:
        if not ips or not ports or self._stop:
            return {}

        sem = asyncio.Semaphore(max_concurrency)
        open_ports: Dict[str, List[int]] = {ip: [] for ip in ips}
        total = len(ips) * len(ports)
        progress = 0

        async def worker(ip: str, port: int):
            nonlocal progress
            if self._stop:
                return
            async with sem:
                if self._stop:
                    return
                is_open = await self._probe_port(ip, port, timeout_s)
                if is_open:
                    open_ports[ip].append(port)
                progress += 1
                if progress % 50 == 0:
                    self.status.emit(f"Port scan progress: {progress}/{total}")

        tasks = [asyncio.create_task(worker(ip, port)) for ip in ips for port in ports]
        await asyncio.gather(*tasks, return_exceptions=True)
        if self._stop:
            return {}
        return {ip: sorted(set(lst)) for ip, lst in open_ports.items() if lst}

    def run(self):
        original_iface = conf.iface
        try:
            if self.iface_name:
                conf.iface = self.iface_name

            devices: Dict[str, Device] = {}

            npcap_available = is_npcap_available()

            # 1) ARP scan
            if npcap_available:
                self.status.emit(f"Scanning {self.cidr} (ARP)...")
                net = ipaddress.IPv4Network(self.cidr, strict=False)
                targets = [str(ip) for ip in net.hosts()]

                conf.verb = 0
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets)

                ans, _ = srp(pkt, timeout=2, retry=1)
                for _, rcv in ans:
                    if self._stop:
                        self.status.emit("Scan stopped.")
                        return
                    ip = rcv.psrc
                    if not ip_in_cidr(ip, self.cidr):
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
                    if not ip_in_cidr(ip, self.cidr):
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
                    if not ip_in_cidr(ip, self.cidr):
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

            # 6) TCP port scan
            if self.do_port_scan and not self._stop:
                ips = list(devices.keys())
                ports = list(range(self.port_start, self.port_end + 1))
                if ips and ports:
                    self.status.emit(
                        f"Scanning TCP ports {self.port_start}-{self.port_end} (timeout {self.port_timeout_ms}ms, concurrency {self.port_concurrency})..."
                    )
                    try:
                        open_map = asyncio.run(
                            self._scan_ports_async(
                                ips=ips,
                                ports=ports,
                                timeout_s=max(0.05, self.port_timeout_ms / 1000.0),
                                max_concurrency=self.port_concurrency,
                            )
                        )
                        for ip, open_ports in open_map.items():
                            if self._stop:
                                self.status.emit("Scan stopped.")
                                return
                            d = self._merge_device(devices, ip)
                            d.protocols.add("TCP")
                            d.open_tcp_ports.extend(open_ports)
                            desc = "Open TCP: " + ",".join(str(p) for p in open_ports)
                            d.description = normalize_description(d.description, desc)
                    except Exception as e:
                        self.status.emit(f"Port scan error: {e}")
                else:
                    self.status.emit("Port scan skipped (no targets).")

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
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Local Network Device Discovery (Windows)")
        self.resize(1180, 680)

        self.oui_map = load_oui_map("oui.csv")
        self.worker: Optional[ScanWorker] = None
        self.devices: List[Device] = []
        self.npcap_available = False

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

        # Port scan controls
        ports = QHBoxLayout()
        layout.addLayout(ports)

        self.cb_portscan = QCheckBox("TCP port scan")
        ports.addWidget(self.cb_portscan)

        ports.addWidget(QLabel("From:"))
        self.sp_port_start = QSpinBox()
        self.sp_port_start.setRange(1, 65535)
        self.sp_port_start.setValue(20)
        ports.addWidget(self.sp_port_start)

        ports.addWidget(QLabel("To:"))
        self.sp_port_end = QSpinBox()
        self.sp_port_end.setRange(1, 65535)
        self.sp_port_end.setValue(1024)
        ports.addWidget(self.sp_port_end)

        ports.addWidget(QLabel("Timeout (ms):"))
        self.sp_port_timeout = QSpinBox()
        self.sp_port_timeout.setRange(50, 10000)
        self.sp_port_timeout.setValue(300)
        ports.addWidget(self.sp_port_timeout)

        ports.addWidget(QLabel("Concurrency:"))
        self.sp_port_concurrency = QSpinBox()
        self.sp_port_concurrency.setRange(1, 1000)
        self.sp_port_concurrency.setValue(200)
        ports.addWidget(self.sp_port_concurrency)

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
        self.cb_portscan.toggled.connect(self._toggle_port_controls)

        self._toggle_port_controls(self.cb_portscan.isChecked())
        self.update_npcap_state()

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

    def _toggle_port_controls(self, checked: bool):
        for w in [
            self.sp_port_start,
            self.sp_port_end,
            self.sp_port_timeout,
            self.sp_port_concurrency,
        ]:
            w.setEnabled(checked)


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

        cidr = it["cidr"]

        port_scan_enabled = self.cb_portscan.isChecked()
        port_start = int(self.sp_port_start.value())
        port_end = int(self.sp_port_end.value())
        port_timeout_ms = int(self.sp_port_timeout.value())
        port_concurrency = int(self.sp_port_concurrency.value())
        if port_scan_enabled:
            if port_start < 1 or port_end > 65535 or port_start > port_end:
                QMessageBox.warning(self, "Invalid ports", "Please choose a TCP port range between 1 and 65535.")
                self.btn_scan.setEnabled(True)
                return
            if port_concurrency < 1:
                QMessageBox.warning(self, "Invalid concurrency", "Port scan concurrency must be at least 1.")
                self.btn_scan.setEnabled(True)
                return
            if port_timeout_ms < 10:
                QMessageBox.warning(self, "Invalid timeout", "Timeout must be at least 10ms.")
                self.btn_scan.setEnabled(True)
                return

        self.table.setRowCount(0)
        self.devices = []
        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.status_lbl.setText(f"Starting scan on {cidr} ...")

        self.worker = ScanWorker(
            cidr=cidr,
            iface_name=it["name"],
            do_ping=self.cb_ping.isChecked(),
            do_mdns=self.cb_mdns.isChecked(),
            do_ssdp=self.cb_ssdp.isChecked(),
            do_rdns=self.cb_rdns.isChecked(),
            fetch_upnp_xml=(self.cb_ssdp.isChecked() and self.cb_upnp_xml.isChecked()),
            mdns_duration_s=int(self.sp_mdns.value()),
            ssdp_timeout_s=int(self.sp_ssdp.value()),
            do_port_scan=port_scan_enabled,
            port_start=port_start,
            port_end=port_end,
            port_timeout_ms=port_timeout_ms,
            port_concurrency=port_concurrency,
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
