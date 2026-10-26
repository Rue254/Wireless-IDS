import time, joblib, pandas as pd
from scapy.all import sniff, Dot11
from collections import deque
from features import featurize

IFACE = "listener"
KNOWN_DEVICES = {"02:00:00:00:00:00": "router", "02:00:00:00:01:00": "phone"}
model, features = joblib.load("wids_model.joblib")
buf, win_start, blocklist = [], None, set()
recent = deque(maxlen=5)
under_attack, reported = False, set()
COLS = ["type", "subtype", "src", "dst", "rssi"]

def log(msg):
    print(msg, flush=True)
    with open("alerts.log", "a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")

def flush():
    global buf, under_attack
    if not buf:
        return
    row = featurize(buf)
    recent.append(1 if row["n_deauth"] >= 5 else 0)
    row["deauth_run"] = sum(recent)
    pred = model.predict(pd.DataFrame([row])[features])[0]
    if pred == 1:
        df = pd.DataFrame(buf, columns=COLS)
        deauth = df[(df.type == 0) & (df.subtype == 12)]
        src = deauth.src.value_counts().index[0] if len(deauth) else "unknown"
        victim = deauth.dst.value_counts().index[0] if len(deauth) else "unknown"
        tag = "STARTED" if not under_attack else "ongoing"
        under_attack = True
        log(f"[ALERT] deauth flood {tag}: {row['n_deauth']} frames/s, src={src}, victim={victim}")
        if src not in reported and src != "unknown":
            reported.add(src)
            if src in KNOWN_DEVICES:
                verdict = f"spoofed ({KNOWN_DEVICES[src]} address), logged only"
            else:
                verdict = "BLOCKED"
                blocklist.add(src)
                with open("blocklist.txt", "a") as f:
                    f.write(f"{time.time()},{src}\n")
            log(f"[WIPS] {src}: {verdict}")
            with open("offenders.csv", "a") as f:
                f.write(f"{time.time()},{src},{victim},{row['n_deauth']},{verdict}\n")
    elif under_attack:
        under_attack = False
        reported.clear()
        log("[INFO] flood ended")
    buf = []

def handle(pkt):
    global win_start
    if not pkt.haslayer(Dot11):
        return
    t = float(pkt.time)
    win_start = win_start or t
    if t - win_start >= 1:
        flush()
        win_start = t
    d = pkt[Dot11]
    buf.append((d.type, d.subtype, d.addr2, d.addr1, getattr(pkt, "dBm_AntSignal", None)))

print(f"WIDS running on {IFACE}... Ctrl+C to stop")
sniff(iface=IFACE, prn=handle, store=False)
