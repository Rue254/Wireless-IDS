import argparse, os
from collections import defaultdict
import pandas as pd
from scapy.all import PcapReader, Dot11

def featurize(frames):
    """frames: list of (type, subtype, src, dst, rssi) from one 1-second window."""
    df = pd.DataFrame(frames, columns=["type", "subtype", "src", "dst", "rssi"])
    deauth = df[(df.type == 0) & (df.subtype == 12)]
    disas = df[(df.type == 0) & (df.subtype == 10)]
    rssi = pd.to_numeric(df.rssi, errors="coerce")
    n = len(df)
    return {
        "n_frames": n,
        "n_mgmt": int((df.type == 0).sum()),
        "n_ctrl": int((df.type == 1).sum()),
        "n_data": int((df.type == 2).sum()),
        "n_deauth": len(deauth),
        "n_disassoc": len(disas),
        "frac_deauth": len(deauth) / n if n else 0,
        "max_frames_per_src": int(df.src.value_counts().max()) if n else 0,
        "max_deauth_per_src": int(deauth.src.value_counts().max()) if len(deauth) else 0,
        "n_unique_src": df.src.nunique(),
        "n_unique_dst": df.dst.nunique(),
        "mean_rssi": rssi.mean() if rssi.notna().any() else -100,
        "std_rssi": rssi.std() if rssi.notna().sum() > 1 else 0,
    }

def extract(pcap, label, session, a_start=None, a_end=None):
    wins, t0 = defaultdict(list), None
    for pkt in PcapReader(pcap):
        if not pkt.haslayer(Dot11):
            continue
        t = float(pkt.time)
        t0 = t if t0 is None else t0
        d = pkt[Dot11]
        wins[int(t - t0)].append((d.type, d.subtype, d.addr2, d.addr1,
                                  getattr(pkt, "dBm_AntSignal", None)))
    rows = []
    for w, frames in sorted(wins.items()):
        row = featurize(frames)
        row["label"] = int(label == 1 and (a_start is None or a_start <= w < a_end))
        row["session"] = session
        rows.append(row)
    out = pd.DataFrame(rows)
    out["deauth_run"] = (out.n_deauth >= 5).astype(int).rolling(5, min_periods=1).sum().astype(int)
    return out

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap"); ap.add_argument("--attack", type=int, default=0)
    ap.add_argument("--session", required=True)
    ap.add_argument("--start", type=int); ap.add_argument("--end", type=int)
    ap.add_argument("--out", default="dataset.csv")
    a = ap.parse_args()
    df = extract(a.pcap, a.attack, a.session, a.start, a.end)
    df.to_csv(a.out, mode="a", header=not os.path.exists(a.out), index=False)
    print(a.pcap, df.label.value_counts().to_dict())
