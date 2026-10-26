import pandas as pd, joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.metrics import accuracy_score, ConfusionMatrixDisplay, classification_report

data = pd.read_csv("dataset.csv")
features = ["n_deauth", "frac_deauth", "max_deauth_per_src", "deauth_run"]

train, test = data[data.session == "s1"], data[data.session == "s2"]
model = DecisionTreeClassifier(max_depth=4, class_weight="balanced", random_state=42)
model.fit(train[features], train.label)

pred = model.predict(test[features])
print("Accuracy:", accuracy_score(test.label, pred))
print(classification_report(test.label, pred, target_names=["normal", "attack"]))
print(export_text(model, feature_names=features))

ConfusionMatrixDisplay.from_predictions(test.label, pred, display_labels=["normal", "attack"])
plt.savefig("confusion_matrix.png", dpi=200)
joblib.dump((model, features), "wids_model.joblib")
