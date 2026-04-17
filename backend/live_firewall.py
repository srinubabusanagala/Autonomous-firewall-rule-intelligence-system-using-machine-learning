import os
import joblib
import pandas as pd
import sqlite3

from backend.live_capture import capture_live
from backend.firewall_actions import log_event, block_ip

# =========================
# PATH CONFIGURATION
# =========================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "ai_firewall_model.pkl")
DB_PATH = os.path.join(BASE_DIR, "logs", "firewall_logs.db")

# =========================
# LOAD MODEL
# =========================

model = joblib.load(MODEL_PATH)

# =========================
# DATABASE INITIALIZATION
# =========================

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        timestamp REAL,
        src_ip TEXT,
        dst_ip TEXT,
        protocol TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        length INTEGER,
        label TEXT,
        action TEXT
    )
    """)

    conn.commit()
    conn.close()

# =========================
# MAIN FIREWALL LOOP
# =========================

def run_firewall(interface=None):
    print("AI Firewall Running...")
    init_db()   # <-- GUARANTEED DB + TABLE

    for packet in capture_live(interface):
        try:
            features = pd.DataFrame([{
                "src_port": packet["src_port"],
                "dst_port": packet["dst_port"],
                "length": packet["length"]
            }])

            prediction = model.predict(features)[0]

            if prediction == 1:
                print(f"[LIVE CAPTURE] Label: Malicious | Action: Blocked | Packet: {packet}")
                block_ip(packet["src_ip"])
                log_event(packet, "Malicious", "Blocked")
            else:
                print(f"[LIVE CAPTURE] Label: Benign | Action: Allowed | Packet: {packet}")
                log_event(packet, "Benign", "Allowed")

        except Exception as e:
            print("Skipped packet:", e)

# =========================
# ENTRY POINT
# =========================

if __name__ == "__main__":
    run_firewall()
