#!/usr/bin/env python3
"""Modern concurrent TCP port scanner with robust CLI and error handling."""
from __future__ import annotations

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Sequence

try:  # Optional, improves UX when available
    from tqdm import tqdm
except Exception:  # pragma: no cover - tqdm may not be installed
    tqdm = None  # type: ignore


def parse_ports(port_string: str) -> List[int]:
    """Parse flexible port input into a sorted list of unique integers.

    Accepted examples: ``"1-1024"``, ``"80,443"``, ``"20-25,8080"``.

    Args:
        port_string: Comma-separated list of single ports or inclusive ranges.

    Returns:
        Sorted list of unique port numbers.

    Raises:
        argparse.ArgumentTypeError: If the input is malformed or out of range.
    """

    def _parse_token(token: str) -> Sequence[int]:
        if "-" in token:
            start_s, end_s = token.split("-", 1)
            try:
                start, end = int(start_s), int(end_s)
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port range: {token}")
            if start > end:
                raise argparse.ArgumentTypeError(
                    f"Port range start exceeds end: {token}"
                )
            return range(start, end + 1)
        try:
            return [int(token)]
        except ValueError:
            raise argparse.ArgumentTypeError(f"Invalid port value: {token}")

    ports: set[int] = set()
    tokens = [t.strip() for t in port_string.split(",") if t.strip()]
    if not tokens:
        raise argparse.ArgumentTypeError("At least one port must be specified")

    for token in tokens:
        for port in _parse_token(token):
            if not 1 <= port <= 65535:
                raise argparse.ArgumentTypeError(
                    f"Port out of valid range (1-65535): {port}"
                )
            ports.add(port)

    return sorted(ports)


def scan_port(target: str, port: int, timeout: float) -> bool:
    """Attempt to connect to a TCP port.

    Args:
        target: IP address of the target host.
        port: Port number to check.
        timeout: Per-connection timeout in seconds.

    Returns:
        ``True`` when the port is open, ``False`` otherwise.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((target, port))
        except socket.timeout:
            return False
        except socket.gaierror:
            # Should not occur after pre-scan resolution, but handled defensively.
            return False
        return result == 0


def resolve_target(hostname: str) -> str:
    """Resolve a hostname to an IPv4 address.

    Raises:
        SystemExit: with a clear message if resolution fails.
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as exc:  # pragma: no cover - depends on network
        raise SystemExit(f"Failed to resolve '{hostname}': {exc}") from exc


def scan_targets(
    ip: str, ports: Iterable[int], timeout: float, max_workers: int
) -> List[int]:
    """Scan ports concurrently and return a list of open ports."""
    ports_list = list(ports)
    open_ports: List[int] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(scan_port, ip, port, timeout): port for port in ports_list}

        if tqdm is not None:
            for future in tqdm(
                as_completed(future_map),
                total=len(ports_list),
                desc="Scanning",
                unit="port",
            ):
                port = future_map[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception as exc:  # pragma: no cover - defensive catch
                    sys.stderr.write(f"Error scanning port {port}: {exc}\n")
        else:
            for future in as_completed(future_map):
                port = future_map[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception as exc:  # pragma: no cover - defensive catch
                    sys.stderr.write(f"Error scanning port {port}: {exc}\n")

    return sorted(open_ports)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Concurrent TCP port scanner")
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target hostname or IP address",
    )
    parser.add_argument(
        "-p",
        "--ports",
        required=True,
        type=parse_ports,
        help="Ports to scan (e.g. 1-1024,80,443)",
    )
    parser.add_argument(
        "-j",
        "--threads",
        type=int,
        default=50,
        help="Maximum number of concurrent threads (default: 50)",
    )
    parser.add_argument(
        "-w",
        "--timeout",
        type=float,
        default=1.0,
        help="Socket timeout in seconds (default: 1.0)",
    )
    return parser


def format_results(target: str, ip: str, open_ports: Sequence[int], elapsed: float) -> str:
    lines = [
        f"Scan results for {target} ({ip})",
        f"Time elapsed: {elapsed:.2f}s",
        "Open ports:" if open_ports else "No open ports found.",
    ]

    for port in open_ports:
        lines.append(f"  - {port}/tcp open")

    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        ports = args.ports
    except argparse.ArgumentTypeError as exc:  # pragma: no cover - handled by argparse
        parser.error(str(exc))

    if args.threads < 1:
        parser.error("--threads must be at least 1")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    ip = resolve_target(args.target)
    print(f"Resolved {args.target} -> {ip}")

    start = time.perf_counter()
    open_ports = scan_targets(ip, ports, timeout=args.timeout, max_workers=args.threads)
    elapsed = time.perf_counter() - start

    print(format_results(args.target, ip, open_ports, elapsed))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
