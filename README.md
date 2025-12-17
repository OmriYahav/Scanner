# Scanner Host + Mobile

This repository now contains a LAN-only host (Python) and a companion Expo/React Native client for discovery, pairing, and running tests against the existing scanning engine.

## Host (Python, FastAPI)

### Features
- Serves REST + WebSocket API with a local dashboard at `http://localhost:8000/`.
- Publishes `_netlinker._tcp.local` via mDNS/Bonjour for device discovery.
- In-memory secure pairing flow (6-digit code) that issues bearer tokens.
- Presence tracking via WebSocket heartbeat so the dashboard can show connected phones.
- Reuses existing `netscan.py` logic through `scanner_host/engine/netscan_adapter.py` (engine remains Python).

### Running locally (Windows-friendly)
1. Create and activate a virtual environment.
2. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```
3. Start the host:
   ```bash
   python main.py
   ```
4. Open the dashboard at [http://localhost:8000](http://localhost:8000) to view status, pairing code, and connected devices.

> mDNS advertisement relies on the `zeroconf` Python package. If you need ARP/packet features from the legacy scanner, install Npcap and run with elevated permissions on Windows.

### API overview
- `GET /status` — host metadata + connected devices
- `POST /pair/start` — begin a pairing session
- `GET /pair/code` — fetch current 6-digit code
- `POST /pair/confirm` — { code, device_id, device_name } → { token }
- `POST /tests/ping` — authenticated; pings a target using the legacy engine
- `WS /ws` — mobile connects, sends `hello` with token/device_id/device_name, then heartbeat every ~10s

Tokens are stored in-memory for now; the code is structured to allow persistence later.

## Mobile (Expo + Dev Client)

The `mobile/` directory is an Expo project configured for mDNS (Bonjour) discovery using `react-native-zeroconf`.

### Stack
- Expo (Dev Client) with React Native
- `react-native-zeroconf` for mDNS discovery
- `expo-secure-store` for storing pairing tokens
- Fetch for REST, WebSocket for realtime presence

### Setup & run
```bash
cd mobile
npm install
npx expo prebuild
npx expo run:android   # or expo run:ios
```

mDNS browsing requires a Dev Client/EAS build because it needs native modules. On device, open the app and wait for hosts to appear automatically. Select a host, enter the 6-digit code from the PC dashboard, and the app will store the token and keep a WebSocket heartbeat so the PC shows it as connected.

### Fallback discovery
mDNS is the primary discovery method. If a platform build does not support mDNS, add UDP broadcast discovery as a secondary mechanism.

## Repository layout
```
scanner_host/
  api/            FastAPI routes + websocket presence
  auth/           Pairing + token handling
  discovery/      mDNS advertisement
  engine/         Wrappers around legacy netscan
  webui/          Static dashboard served by the host
main.py           Entrypoint to start the host
netscan.py        Existing scanning logic (unchanged)
mobile/           Expo project for the client
```
