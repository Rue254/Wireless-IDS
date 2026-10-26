import pandas as pd
from features import extract
from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.metrics import confusion_matrix, accuracy_score

def build(items):
    return pd.concat([extract(p, a, s, st, en) for p, a, s, st, en in items], ignore_index=True)

# BEFORE: train on original captures only, all simple features
tr = build([("normal_1.pcap",0,"s1",None,None), ("attack_1.pcap",1,"s1",30,60)])
te = build([("normal_2.pcap",0,"s2",None,None), ("attack_slow_2.pcap",1,"s2",30,60)])
old = [c for c in tr.columns if c not in ("label","session","mean_rssi","std_rssi","deauth_run")]
m = DecisionTreeClassifier(max_depth=4, class_weight="balanced", random_state=42).fit(tr[old], tr.label)
p = m.predict(te[old])
print("BEFORE (tested on slow attack)\n", confusion_matrix(te.label, p), "acc", round(accuracy_score(te.label, p), 3))
print(export_text(m, feature_names=old))

# AFTER: add slow attacks and deauth_run
tr = build([("normal_1.pcap",0,"s1",None,None), ("attack_1.pcap",1,"s1",30,60), ("attack_slow_1.pcap",1,"s1",30,60)])
te = build([("normal_2.pcap",0,"s2",None,None), ("attack_2.pcap",1,"s2",30,60), ("attack_slow_2.pcap",1,"s2",30,60)])
new = ["n_deauth","frac_deauth","max_deauth_per_src","deauth_run"]
m = DecisionTreeClassifier(max_depth=4, class_weight="balanced", random_state=42).fit(tr[new], tr.label)
p = m.predict(te[new])
print("AFTER\n", confusion_matrix(te.label, p), "acc", round(accuracy_score(te.label, p), 3))
print(export_text(m, feature_names=new))
