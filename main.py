import logging
import uvicorn

from scanner_host.api.app import build_app
from scanner_host.discovery.mdns import MdnsAdvertiser
from scanner_host.settings import get_settings

logging.basicConfig(level=logging.INFO)


def main():
    settings = get_settings()
    advertiser = MdnsAdvertiser(settings)
    app = build_app(settings, advertiser)
    uvicorn.run(app, host="0.0.0.0", port=settings.api_port)


if __name__ == "__main__":
    main()
