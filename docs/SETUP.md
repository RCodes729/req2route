# Setup guide (Windows, about 5 minutes)

## You need
- Google Chrome 116 or newer
- Python 3.10 or newer from [python.org](https://www.python.org/downloads/). During install, tick **Add python.exe to PATH**.
- The repo, cloned or downloaded: `git clone <repo-url>`

## 1. Load the extension
1. Open `chrome://extensions`.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and choose the `extension` folder inside the repo.
4. Req2Route appears in the list. After pulling new code, click its **reload** ↻ button.

## 2. Use it
1. Open any website, for example `https://www.wikipedia.org`.
2. Press **F12** to open DevTools. Find the **Req2Route** tab (it may be under the `»` menu).
3. Click **Analyze this page**. The page reloads and every request appears.
4. Click a request to see its layer-by-layer explanation.
5. Open the **Experiment** tab for the simulators.

## 3. Start the helper (for the Live tests tab)
Double-click `helper\start-helper.bat`. It opens two windows:
- **Req2Route echo server** on port 9000, the team-controlled target for TCP/UDP tests
- **Req2Route helper** on `http://127.0.0.1:8765`

In the extension's **Live tests** tab, click **Check helper**. You should see `"ok": true`.

Optional: `pip install dnspython` makes the DNS test show TTL, CNAME, MX and NS records.

To test with real packet loss, close the echo window and run:
```
cd helper
python echo_server.py --port 9000 --loss 10 --delay 40
```

## Troubleshooting
| Problem | Fix |
|---|---|
| No Req2Route tab in DevTools | Close and reopen DevTools after loading the extension |
| Request list is empty | Click **Analyze this page**; DevTools only sees requests made while it is open |
| "Helper not reachable" | Check the helper window is still open; run `python helper\server.py` to see errors |
| TCP/UDP test says "not an approved test target" | Only hosts in `helper\config.json` can be tested; add only machines your team controls |
| Firewall prompt | Allow on **Private networks** |
| ARP table empty | Normal on some VPNs; open a local site (your router page) first, then retry |
