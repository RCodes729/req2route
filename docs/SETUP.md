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
3. Click **Analyze**. The page reloads and every request appears.
4. Click a request to see its layer-by-layer explanation.
5. Open the **Experiment** tab for the simulators.

## 3. Start the helper (for the Live tab)
Double-click `helper\start-helper.bat`. It opens two windows:
- **Req2Route echo server** on port 9000, the team-controlled target for TCP/UDP tests
- **Req2Route helper** on `http://127.0.0.1:8765`

In the extension's **Live** tab, click **Check helper**. You should see `"ok": true`.

Optional: `pip install dnspython` makes the DNS test show TTL, CNAME, MX and NS records.

To test with real packet loss, close the echo window and run:
```
cd helper
python echo_server.py --port 9000 --loss 10 --delay 40
```

## Helper config (optional)
Copy `helper\config.example.json` to `helper\config.json` to change the defaults. Two keys control access:
- `allowed_ports`: the ports TCP/UDP tests may use (default `[9000]`). An empty or missing list allows no port, so every TCP/UDP test is refused.
- `allowed_extension_ids`: a list of extension IDs allowed to call the helper (default `[]`). Empty means any Chrome extension can call it. To pin it to Req2Route, open `chrome://extensions`, turn on **Developer mode**, copy the **ID** shown on the Req2Route card, and set `"allowed_extension_ids": ["<that id>"]`. To confirm the pin took effect, open `http://127.0.0.1:8765/health` (for example with `curl http://127.0.0.1:8765/health`); the helper reports `"extensionPinned": true` there. The **Check helper** panel does not display this field. IDs must be 32 letters a-p; a malformed config stops the helper at startup with a clear message.

Restart the helper after editing the file.

## Troubleshooting
| Problem | Fix |
|---|---|
| No Req2Route tab in DevTools | Close and reopen DevTools after loading the extension |
| Request list is empty | Click **Analyze**; DevTools only sees requests made while it is open |
| "Helper not reachable" | Check the helper window is still open; run `python helper\server.py` to see errors |
| TCP handshake says `Connection refused` (`WinError 10061`) | The target is approved but nothing is listening on it. Port 9000 needs the **echo server**, which is a separate program from the helper: run `helper\start-helper.bat` (it opens both), or `python helper\echo_server.py --port 9000`. **Check helper** now shows whether each approved `host:port` is listening. Restart the helper after pulling new code |
| TCP/UDP test says "not an approved test target" | Only hosts in `helper\config.json` can be tested; add only machines your team controls |
| Firewall prompt | Allow on **Private networks** |
| ARP table empty | Normal on some VPNs; open a local site (your router page) first, then retry |
| `npm : File ... npm.ps1 cannot be loaded because running scripts is disabled` | Windows PowerShell blocks npm's script wrapper. Use `npm.cmd test`, or run once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` and reopen PowerShell |
| `The token '&&' is not a valid statement separator` | Windows PowerShell 5.1 has no `&&`. Run the commands on separate lines, or join them with `;` |
| `start-helper.bat` says Python was not found, but typing `python` opens the Microsoft Store | That is only a placeholder. Install Python from python.org and tick **Add python.exe to PATH** |
| GitHub CI fails after ~3 s with *account is locked due to a billing issue* | Not a code problem: Actions did not start. Run `npm.cmd test` and `python -m unittest discover -s helper/tests` locally and paste the pass counts in the PR |
