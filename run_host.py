"""Entry point for running the embedded host without pulling in scan logic."""

from scanner_host.runtime import HostRuntime


def main() -> None:
    HostRuntime().run()


if __name__ == "__main__":
    main()
