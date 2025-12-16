import sys
import csv
import time
import webbrowser
import socket
import ipaddress
import threading
import xml.etree.ElementTree as ET
import errno
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, Set, List, Dict, Tuple
import subprocess
import ctypes
from multiprocessing import cpu_count

import psutil
import requests
from ping3 import ping

from scapy.all import ARP, Ether, srp, conf  # type: ignore

from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange  # type: ignore

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QComboBox, QTableWidget, QTableWidgetItem,
    QFileDialog, QCheckBox, QSpinBox, QMessageBox, QLineEdit
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
    except Exception:
        return False

    if not sock:
        return False

    try:
        sock.close()
    except Exception:
        pass
    return True


def is_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
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

        self.last_hit = time.time()

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

            self.last_hit = time.time()

        except Exception:
            return

    def run(self) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
        try:
            for t in self.COMMON_TYPES:
                self.browsers.append(ServiceBrowser(self.zc, t, handlers=[self._on_state_change]))
            start = time.time()
            while True:
                now = time.time()
                if now - start >= self.duration_s:
                    break
                if now - self.last_hit > 1.2 and now - start > 1.0:
                    break
                time.sleep(0.1)
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
    last_packet = time.time()

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
                if time.time() - last_packet > 0.5:
                    break
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

            last_packet = time.time()

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
        full_subnet_scan: bool,
        mdns_duration_s: int,
        ssdp_timeout_s: int,
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
        self.full_subnet_scan = full_subnet_scan
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
            ping_results: Dict[str, float] = {}

            npcap_available = is_npcap_available()

            net = ipaddress.IPv4Network(self.cidr, strict=False)
            targets = [str(ip) for ip in net.hosts()]

            max_ping_workers = min(256, cpu_count() * 8)

            def icmp_ping(ip: str) -> Optional[float]:
                try:
                    res = ping(ip, timeout=0.6, unit="ms")
                    return float(res) if res is not None else None
                except Exception:
                    return None

            def run_ping_pool():
                if not self.do_ping or not targets:
                    return
                total = len(targets)
                completed = 0
                last_emit = 0.0
                with ThreadPoolExecutor(max_workers=max_ping_workers) as executor:
                    future_map = {executor.submit(icmp_ping, ip): ip for ip in targets}
                    for fut in as_completed(future_map):
                        if self._stop:
                            executor.shutdown(cancel_futures=True)
                            return
                        ip = future_map[fut]
                        rtt = fut.result()
                        if rtt is not None:
                            ping_results[ip] = rtt
                        completed += 1
                        now = time.time()
                        if now - last_emit >= 0.2:
                            self.status.emit(f"ICMP ping: {completed}/{total} hosts probed")
                            last_emit = now

            ping_thread = threading.Thread(target=run_ping_pool, daemon=True)
            ping_thread.start()

            t_start = time.perf_counter()

            # 1) ARP scan
            if npcap_available:
                self.status.emit(f"Scanning {self.cidr} (ARP)...")

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

            arp_end = time.perf_counter()
            print(f"[TIMING] ARP duration: {(arp_end - t_start):.3f}s")

            # 2) SSDP and mDNS in parallel with ping
            ssdp_data: Dict[str, dict] = {}
            mdns_names: Dict[str, Set[str]] = {}
            mdns_services: Dict[str, Set[str]] = {}

            def run_ssdp():
                nonlocal ssdp_data
                if not self.do_ssdp or self._stop:
                    return
                self.status.emit(f"Discovering UPnP/SSDP (timeout {self.ssdp_timeout_s}s)...")
                ssdp_data = ssdp_discover(timeout_s=self.ssdp_timeout_s, mx=2)

            def run_mdns():
                nonlocal mdns_names, mdns_services
                if not self.do_mdns or self._stop:
                    return
                self.status.emit(f"Discovering mDNS/Bonjour (listening {self.mdns_duration_s}s)...")
                collector = MDNSCollector(duration_s=self.mdns_duration_s)
                mdns_names, mdns_services = collector.run()

            ssdp_thread = threading.Thread(target=run_ssdp, daemon=True)
            mdns_thread = threading.Thread(target=run_mdns, daemon=True)

            ssdp_thread.start()
            mdns_thread.start()

            ssdp_thread.join()
            mdns_thread.join()

            mdns_end = time.perf_counter()
            if self.do_mdns:
                for ip, names in mdns_names.items():
                    if self._stop:
                        self.status.emit("Scan stopped.")
                        return
                    if not ip_in_cidr(ip, self.cidr):
                        continue
                    d = self._merge_device(devices, ip)
                    d.protocols.add("mDNS")
                    for n in names:
                        d.mdns_names.add(n)
                    if not d.hostname and d.mdns_names:
                        d.hostname = sorted(d.mdns_names)[0]
                    svcs = mdns_services.get(ip, set())
                    if svcs:
                        d.description = normalize_description(d.description, "mDNS: " + ",".join(sorted(svcs)[:6]))

            if self.do_ssdp:
                for ip, info in ssdp_data.items():
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

                    desc_bits = []
                    if d.ssdp_st:
                        desc_bits.append(d.ssdp_st)
                    if d.ssdp_server:
                        desc_bits.append(d.ssdp_server)
                    if desc_bits:
                        d.description = normalize_description(d.description, "UPnP: " + " | ".join(desc_bits[:2]))

            ssdp_end = time.perf_counter()

            if self.fetch_upnp_xml and self.do_ssdp and not self._stop:
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

            ping_thread.join()
            ping_end = time.perf_counter()

            if self.do_ping and not self._stop:
                for ip, rtt in ping_results.items():
                    if not ip_in_cidr(ip, self.cidr):
                        continue
                    d = self._merge_device(devices, ip)
                    d.rtt_ms = rtt
                    d.protocols.add("ICMP")

            # 4) TCP fallback for unreachable hosts (full subnet)
            if self.full_subnet_scan and not self._stop:
                remaining_targets = [ip for ip in targets if ip not in devices]
                total = len(remaining_targets)

                def tcp_probe(ip: str) -> Tuple[bool, Optional[float]]:
                    tcp_ports = [80, 443, 22, 445, 3389]
                    for port in tcp_ports:
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(0.3)
                            start_ts = time.time()
                            res = sock.connect_ex((ip, port))
                            elapsed_ms = (time.time() - start_ts) * 1000.0
                            sock.close()
                            if res == 0 or res in (errno.ECONNREFUSED, 111, 10061):
                                return True, elapsed_ms if res == 0 else None
                        except Exception:
                            pass
                    return False, None

                if total:
                    checked = 0
                    alive_count = 0
                    last_emit = 0.0
                    self.status.emit(f"Probing subnet: 0/{total} checked – 0 alive")
                    with ThreadPoolExecutor(max_workers=64) as executor:
                        future_map = {executor.submit(tcp_probe, ip): ip for ip in remaining_targets}
                        for fut in as_completed(future_map):
                            if self._stop:
                                self.status.emit("Scan stopped.")
                                executor.shutdown(cancel_futures=True)
                                return
                            ip = future_map[fut]
                            checked += 1
                            alive, rtt = fut.result()
                            if alive:
                                alive_count += 1
                                d = self._merge_device(devices, ip)
                                if rtt is not None and d.rtt_ms is None:
                                    d.rtt_ms = rtt
                                d.protocols.add("TCP")
                            now = time.time()
                            if now - last_emit > 0.2:
                                self.status.emit(f"Probing subnet: {checked}/{total} checked – {alive_count} alive")
                                last_emit = now
                    self.status.emit(f"Probing subnet: {total}/{total} checked – {alive_count} alive")

            # 5) Reverse DNS
            if self.do_rdns and not self._stop:
                self.status.emit("Resolving hostnames (Reverse DNS)...")

                def rdns_lookup(ip: str) -> Optional[str]:
                    try:
                        orig_timeout = socket.getdefaulttimeout()
                        socket.setdefaulttimeout(0.3)
                        return safe_gethostbyaddr(ip)
                    finally:
                        socket.setdefaulttimeout(orig_timeout)

                rdns_targets = [
                    (ip, d) for ip, d in devices.items()
                    if (not d.hostname or "mDNS" not in d.protocols) and ("ICMP" in d.protocols or not d.hostname)
                ]
                if rdns_targets:
                    with ThreadPoolExecutor(max_workers=32) as executor:
                        future_map = {executor.submit(rdns_lookup, ip): (ip, d) for ip, d in rdns_targets}
                        for fut in as_completed(future_map):
                            if self._stop:
                                executor.shutdown(cancel_futures=True)
                                return
                            ip, d = future_map[fut]
                            name = fut.result()
                            if name:
                                d.hostname = name
                                d.protocols.add("rDNS")

            total_end = time.perf_counter()
            print(f"[TIMING] mDNS duration: {(mdns_end - arp_end):.3f}s")
            print(f"[TIMING] SSDP duration: {(ssdp_end - arp_end):.3f}s")
            print(f"[TIMING] Ping duration: {(ping_end - t_start):.3f}s")
            print(f"[TIMING] Total scan duration: {(total_end - t_start):.3f}s")

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

        self.oui_map = build_oui_map("oui.csv")  # optional next to script/exe
        self.worker: Optional[ScanWorker] = None
        self.devices: List[Device] = []
        self.npcap_available = False
        self.is_admin_user = is_admin()
        self.arp_available = False
        self.cidr_dirty = False

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)

        # Top controls
        top = QHBoxLayout()
        layout.addLayout(top)

        top.addWidget(QLabel("Interface:"))
        self.if_combo = QComboBox()
        top.addWidget(self.if_combo, 3)

        range_layout = QHBoxLayout()
        range_layout.addWidget(QLabel("Scan range (CIDR):"))
        self.cidr_input = QLineEdit()
        range_layout.addWidget(self.cidr_input, 2)
        range_layout.addStretch(1)
        layout.addLayout(range_layout)

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

        timing.addStretch(1)

        self.btn_scan = QPushButton("Start Scan")
        self.btn_stop = QPushButton("Stop Scan")
        self.btn_export = QPushButton("Export CSV")
        self.btn_install_npcap = QPushButton("Install Npcap")
        self.btn_install_npcap.setVisible(False)
        self.btn_restart_admin = QPushButton("Restart as Admin")
        self.btn_restart_admin.setVisible(False)
        self.btn_stop.setEnabled(False)
        timing.addWidget(self.btn_scan)
        timing.addWidget(self.btn_stop)
        timing.addWidget(self.btn_export)
        timing.addWidget(self.btn_install_npcap)
        timing.addWidget(self.btn_restart_admin)

        self.status_lbl = QLabel("Ready.")
        layout.addWidget(self.status_lbl)

        self.capability_lbl = QLabel("")
        self.capability_lbl.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(self.capability_lbl)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["IP", "MAC Address", "MAC Vendor", "Hostname", "Ping (ms)", "Protocols", "Description"]
        )
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)

        self.load_interfaces()

        self.if_combo.currentIndexChanged.connect(self.on_iface_changed)
        self.cidr_input.textEdited.connect(self.on_cidr_edited)
        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_export.clicked.connect(self.export_csv)
        self.btn_install_npcap.clicked.connect(self.open_npcap_download)
        self.btn_restart_admin.clicked.connect(self.restart_as_admin)

        self.on_iface_changed(self.if_combo.currentIndex())
        self.update_npcap_state()

    def update_npcap_state(self):
        self.npcap_available = is_npcap_available()
        self.is_admin_user = is_admin()
        self.arp_available = self.npcap_available and self.is_admin_user
        self.btn_install_npcap.setVisible(not self.npcap_available)
        self.btn_restart_admin.setVisible(sys.platform == "win32" and not self.is_admin_user)
        if self.npcap_available:
            if self.status_lbl.text().startswith("Npcap is not installed"):
                self.status_lbl.setText("Ready.")
        else:
            self.status_lbl.setText("Npcap is not installed. ARP (MAC discovery) is disabled.")

        npcap_text = "Installed" if self.npcap_available else "Missing"
        admin_text = "Yes" if self.is_admin_user else "No"
        arp_text = "Available" if self.arp_available else "Disabled"
        self.capability_lbl.setText(
            f"Npcap: {npcap_text}   |   Admin: {admin_text}   |   ARP: {arp_text}"
        )
        color = "green" if (self.is_admin_user and self.arp_available) else "red"
        self.capability_lbl.setStyleSheet(f"color: {color}; font-size: 11px;")

    def open_npcap_download(self):
        webbrowser.open("https://npcap.com/#download")

    def restart_as_admin(self):
        if sys.platform != "win32":
            return
        try:
            params_list = sys.argv[1:]
            if not getattr(sys, "frozen", False):
                params_list = [sys.argv[0]] + params_list
            params = subprocess.list2cmdline(params_list)
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1
            )
        except Exception as e:
            QMessageBox.warning(self, "Restart failed", f"Could not restart as admin: {e}")
            return
        QApplication.instance().quit()


    def _set_cidr_text(self, cidr: str):
        self.cidr_input.blockSignals(True)
        self.cidr_input.setText(cidr)
        self.cidr_input.blockSignals(False)
        self.cidr_dirty = False

    def on_iface_changed(self, idx: int):
        it = self.if_combo.itemData(idx)
        if not it:
            return
        if not self.cidr_dirty:
            self._set_cidr_text(it["cidr"])

    def on_cidr_edited(self, _text: str):
        self.cidr_dirty = True

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

        cidr_text = self.cidr_input.text().strip()
        if not cidr_text:
            QMessageBox.warning(self, "Invalid CIDR", "Please enter a CIDR range to scan (e.g., 192.168.1.0/24).")
            return
        try:
            net = ipaddress.IPv4Network(cidr_text, strict=False)
        except Exception:
            QMessageBox.warning(self, "Invalid CIDR", "Please enter a valid IPv4 CIDR (e.g., 192.168.1.0/24).")
            return

        if net.num_addresses > 4096:
            QMessageBox.warning(
                self,
                "Range too large",
                "Please choose a CIDR with 4096 hosts or fewer to avoid excessively large scans.",
            )
            return

        cidr = str(net)

        self.table.setRowCount(0)
        self.devices = []
        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.status_lbl.setText(f"Starting scan on {cidr} ...")

        self.worker = ScanWorker(
            cidr=cidr,
            iface_name=it["name"],
            do_ping=self.cb_ping.isChecked(),
            full_subnet_scan=True,
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
        self.show_mac_guidance_if_needed()

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

            if not d.mac:
                tint = QColor(255, 248, 220)
                for col in range(7):
                    item = self.table.item(row, col)
                    item.setBackground(tint)

        self.table.setSortingEnabled(True)

    def show_mac_guidance_if_needed(self):
        total = len(self.devices)
        if total == 0:
            return
        mac_count = sum(1 for d in self.devices if d.mac)
        if mac_count == 0 or (mac_count / total) < 0.05:
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Information)
            msg.setWindowTitle("Why MAC addresses may be missing")
            msg.setText(
                "MAC discovery requires ARP (Layer 2) on the same broadcast domain.\n\n"
                "Full subnet scan (ICMP/mDNS/SSDP/TCP) can find devices even when ARP cannot.\n\n"
                "To see MACs:\n"
                " • Install Npcap\n"
                " • Run as Administrator\n"
                " • Scan devices on the same VLAN/L2 segment (Wi-Fi isolation/VLANs may block ARP)"
            )
            msg.setStandardButtons(QMessageBox.Ok)
            msg.setModal(False)
            msg.show()

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
