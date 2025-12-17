import sys
import time
import socket
import ipaddress
import threading
import xml.etree.ElementTree as ET
import errno
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, Set, List, Dict, Tuple
import ctypes
from multiprocessing import cpu_count

import psutil
import requests
from ping3 import ping

from scapy.all import ARP, Ether, srp, conf  # type: ignore

from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange  # type: ignore

from PySide6.QtCore import QThread, Signal


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


__all__ = [
    "Device",
    "get_active_ipv4_interfaces",
    "build_oui_map",
    "vendor_from_mac",
    "safe_gethostbyaddr",
    "ip_in_cidr",
    "normalize_description",
    "is_npcap_available",
    "is_admin",
    "MDNSCollector",
    "ssdp_discover",
    "fetch_upnp_friendly_name",
    "ScanWorker",
    "ping",
]
