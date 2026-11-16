// Client for the optional localhost Python helper (helper/server.py).
// Results from real network tests are labelled "Tested".

export const HELPER_URL = 'http://127.0.0.1:8765';
export const LABEL = 'Tested';
export const TIMEOUT_MS = 15000;

async function call(path, params = {}) {
  const url = new URL(path, HELPER_URL);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, v);
  }
  let res;
  try {
    res = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch (e) {
    // A timeout means the helper IS running but the test itself is slow (e.g. an unreachable DNS server).
    if (e?.name === 'TimeoutError') {
      throw new Error(`The helper is running but ${path} took longer than ${TIMEOUT_MS / 1000} s. A DNS server or test target may be slow or unreachable; try again.`);
    }
    throw new Error('Helper not reachable. Start it with: python helper/server.py');
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `Helper returned HTTP ${res.status}`);
  return { ...body, label: LABEL };
}

export const helper = {
  health: () => call('/health'),
  dns: name => call('/dns', { name }),
  resolvers: name => call('/resolvers', { name }),
  tcp: (host, port) => call('/tcp', { host, port }),
  udp: (host, port, count) => call('/udp', { host, port, count }),
  arp: () => call('/arp'),
};
