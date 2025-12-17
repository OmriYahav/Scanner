import React, { useEffect, useMemo, useRef, useState } from 'react';
import { SafeAreaView, View, Text, Button, FlatList, TextInput, StyleSheet } from 'react-native';
import Zeroconf from 'react-native-zeroconf';
import * as SecureStore from 'expo-secure-store';

const SERVICE = '_netlinker._tcp.';

function useDeviceId() {
  const [id] = useState(() => 'mobile-' + Math.random().toString(36).slice(2, 8));
  return id;
}

export default function App() {
  const deviceId = useDeviceId();
  const [deviceName, setDeviceName] = useState('Expo Device');
  const [hosts, setHosts] = useState([]);
  const [selectedHost, setSelectedHost] = useState(null);
  const [pairCode, setPairCode] = useState('');
  const [token, setToken] = useState(null);
  const [status, setStatus] = useState('Discovering hosts...');
  const [pingResult, setPingResult] = useState(null);
  const wsRef = useRef(null);
  const zeroconfRef = useRef(new Zeroconf());

  useEffect(() => {
    const zc = zeroconfRef.current;
    const onResolved = (service) => {
      setHosts((prev) => {
        const filtered = prev.filter((h) => h.name !== service.name);
        const host = {
          name: service.name,
          host: service.addresses?.[0],
          port: service.port,
        };
        return [...filtered, host];
      });
    };
    zc.on('resolved', onResolved);
    zc.scan(SERVICE, 'local.');
    return () => {
      zc.removeListener('resolved', onResolved);
      zc.stop();
    };
  }, []);

  useEffect(() => {
    const load = async () => {
      const saved = await SecureStore.getItemAsync('scanner_credentials');
      if (saved) {
        const parsed = JSON.parse(saved);
        setSelectedHost(parsed.host);
        setToken(parsed.token);
        setDeviceName(parsed.deviceName || 'Expo Device');
      }
    };
    load();
  }, []);

  useEffect(() => {
    if (token && selectedHost) {
      openSocket(selectedHost, token);
      SecureStore.setItemAsync(
        'scanner_credentials',
        JSON.stringify({ host: selectedHost, token, deviceName })
      );
    }
  }, [token, selectedHost, deviceName]);

  const openSocket = (host, tkn) => {
    if (!host) return;
    const ws = new WebSocket(`ws://${host.host}:${host.port}/ws`);
    wsRef.current = ws;
    ws.onopen = () => {
      ws.send(JSON.stringify({ type: 'hello', token: tkn, device_id: deviceId, device_name: deviceName }));
      setStatus(`Connected to ${host.name}`);
    };
    ws.onmessage = () => {
      // ack
    };
    ws.onclose = () => setStatus('Socket closed');
    ws.onerror = () => setStatus('Socket error');
    const interval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'heartbeat', device_id: deviceId }));
      }
    }, 10000);
    ws._heartbeat = interval;
  };

  const confirmPairing = async () => {
    if (!selectedHost) return;
    const res = await fetch(`http://${selectedHost.host}:${selectedHost.port}/pair/confirm`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: pairCode, device_id: deviceId, device_name: deviceName }),
    });
    if (!res.ok) {
      setStatus('Pairing failed');
      return;
    }
    const data = await res.json();
    setToken(data.token);
    setStatus('Paired');
  };

  const runPing = async () => {
    if (!selectedHost || !token) return;
    const res = await fetch(`http://${selectedHost.host}:${selectedHost.port}/tests/ping`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ target: selectedHost.host }),
    });
    const data = await res.json();
    setPingResult(data);
  };

  const renderHost = ({ item }) => (
    <View style={styles.hostRow}>
      <Text style={styles.hostName}>{item.name}</Text>
      <Text>{item.host}:{item.port}</Text>
      <Button title="Select" onPress={() => setSelectedHost(item)} />
    </View>
  );

  return (
    <SafeAreaView style={styles.container}>
      <Text style={styles.heading}>Scanner Mobile</Text>
      <Text style={styles.small}>Device: {deviceId}</Text>
      <TextInput
        style={styles.input}
        placeholder="Device name"
        value={deviceName}
        onChangeText={setDeviceName}
      />
      <Text style={styles.status}>{status}</Text>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>Discovered hosts</Text>
        <FlatList data={hosts} renderItem={renderHost} keyExtractor={(item) => item.name} />
      </View>

      {selectedHost && (
        <View style={styles.card}>
          <Text style={styles.cardTitle}>Pair with {selectedHost.name}</Text>
          <TextInput
            style={styles.input}
            placeholder="Enter 6-digit code"
            keyboardType="numeric"
            maxLength={6}
            value={pairCode}
            onChangeText={setPairCode}
          />
          <Button title="Confirm" onPress={confirmPairing} />
        </View>
      )}

      {token && (
        <View style={styles.card}>
          <Text style={styles.cardTitle}>Dashboard</Text>
          <Button title="Ping host" onPress={runPing} />
          {pingResult && (
            <Text>Ping RTT: {pingResult.rtt_ms ? `${pingResult.rtt_ms.toFixed(2)} ms` : 'unreachable'}</Text>
          )}
        </View>
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 16, backgroundColor: '#f6f6f6' },
  heading: { fontSize: 24, fontWeight: 'bold' },
  small: { color: '#666', marginBottom: 8 },
  status: { marginVertical: 8 },
  card: { backgroundColor: 'white', padding: 12, borderRadius: 8, marginVertical: 8 },
  cardTitle: { fontWeight: 'bold', marginBottom: 8 },
  input: { backgroundColor: 'white', borderColor: '#ccc', borderWidth: 1, borderRadius: 6, padding: 8, marginVertical: 8 },
  hostRow: { paddingVertical: 8, borderBottomColor: '#eee', borderBottomWidth: 1 },
  hostName: { fontWeight: 'bold' },
});
