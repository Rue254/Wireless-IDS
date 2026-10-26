# Machine-Learning Wireless IDS/IPS: Deauthentication Flood Detection

Ruth Ndunge, Student no. 180413

A WIDS/WIPS that reads 802.11 frames in monitor mode, labels each 1-second window
normal or attack with a scikit-learn Decision Tree, raises an alert, and blocks
unknown offending MAC addresses.

## Ethics and safety
All capture and attack generation was done on an isolated virtual Wi-Fi testbed
(`mac80211_hwsim`) inside my own VM. The attack scripts are for that lab only. Do not
run them against networks you do not own or have permission to test.

## Results
| | Before | After |
|---|---|---|
| Accuracy | 0.861 | 0.980 |
| Attack seconds caught | 1 of 30 | 57 of 60 |
| False alarms | 0 of 179 | 3 of 239 |

"Before" was trained on loud floods only and tested on a slow attack. "After" adds
slow-attack training data and deauth features, and is tested on a held-out session.

## How it works
capture (monitor mode) -> 1-second windows -> features -> Decision Tree -> alert + response

- `features.py`: turns a pcap into per-second features
- `train.py`: trains and evaluates the model, saves `wids_model.joblib`
- `compare.py`: the before and after comparison
- `detect.py`: live detector with the WIPS action (blocklist for unknown MACs)
- `gui.py`: status window (green NORMAL, red ATTACK)
- `scripts/`: lab setup, capture and attack scripts (own virtual lab only)
- `pcaps/`: my six captures; `results/`: dataset, model and confusion matrix

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python features.py normal_1.pcap --session s1     # repeat per capture (see compare.py)
python train.py
python compare.py
```
Live demo (needs Kali and `mac80211_hwsim`): run `scripts/setup_lab.sh`, then
`sudo .venv/bin/python detect.py` and `python gui.py`.

## Limitations
Simulated radios (no real signal strength), a small dataset, and MAC blocking cannot stop
forged floods. 802.11w / WPA3 is the real fix.

## AI use
I used Claude (Anthropic) as a coding assistant to plan the project, draft the scripts and
debug my lab. I built the lab, captured the data and ran every test myself.
