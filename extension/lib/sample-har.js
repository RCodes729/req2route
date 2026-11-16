// A tiny HAR sample so the panel can be developed outside DevTools (open panel.html directly)
// and so the tests have realistic input. Values are illustrative.
export const SAMPLE_ENTRIES = [
  {
    request: { method: 'GET', url: 'https://example.com/', httpVersion: 'http/2.0', headers: [] },
    response: {
      status: 200, statusText: '', httpVersion: 'http/2.0', _transferSize: 1256,
      content: { mimeType: 'text/html' },
      headers: [{ name: 'content-type', value: 'text/html; charset=UTF-8' }, { name: 'cache-control', value: 'max-age=604800' }],
    },
    serverIPAddress: '93.184.215.14',
    connection: '1021',
    time: 182.4,
    timings: { blocked: 2.1, dns: 24.6, connect: 88.3, ssl: 51.2, send: 0.3, wait: 61.8, receive: 5.3 },
  },
  {
    request: { method: 'GET', url: 'https://example.com/style.css', httpVersion: 'http/2.0', headers: [] },
    response: { status: 200, statusText: '', httpVersion: 'http/2.0', _transferSize: 512, content: { mimeType: 'text/css' }, headers: [] },
    serverIPAddress: '93.184.215.14',
    connection: '1021',
    time: 41.0,
    timings: { blocked: 0.8, dns: -1, connect: -1, ssl: -1, send: 0.2, wait: 36.4, receive: 3.6 },
  },
  {
    request: { method: 'GET', url: 'https://www.gstatic.com/font.woff2', httpVersion: 'h3', headers: [] },
    response: { status: 200, statusText: '', httpVersion: 'h3', _transferSize: 18000, content: { mimeType: 'font/woff2' }, headers: [{ name: 'alt-svc', value: 'h3=":443"; ma=2592000' }] },
    serverIPAddress: '142.250.181.67',
    connection: '1188',
    time: 97.5,
    timings: { blocked: 1.0, dns: 12.2, connect: 35.0, ssl: 0, send: 0.2, wait: 40.1, receive: 9.0 },
  },
  {
    request: { method: 'POST', url: 'http://192.168.1.1/api/status', httpVersion: 'HTTP/1.1', headers: [] },
    response: { status: 404, statusText: 'Not Found', httpVersion: 'HTTP/1.1', _transferSize: 230, content: { mimeType: 'application/json' }, headers: [{ name: 'server', value: 'lighttpd' }] },
    serverIPAddress: '192.168.1.1',
    connection: '1301',
    time: 9.4,
    timings: { blocked: 0.5, dns: -1, connect: 2.1, ssl: -1, send: 0.1, wait: 6.0, receive: 0.7 },
  },
];
