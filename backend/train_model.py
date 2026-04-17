import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

df = pd.read_csv("dataset.csv")

X = df[["src_port", "dst_port", "length"]]
y = df["label"]

model = RandomForestClassifier()
model.fit(X, y)

joblib.dump(model, "../models/ai_firewall_model.pkl")
print("Model trained & saved")
