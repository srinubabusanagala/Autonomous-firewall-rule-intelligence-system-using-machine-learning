import os
import sqlite3
import platform

# =========================
# ABSOLUTE SAFE PATHS
# =========================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs")
DB_PATH = os.path.join(LOG_DIR, "firewall_logs.db")

# =========================
# DATABASE INITIALIZATION
# =========================

def init_db():
    """Create logs folder and database safely"""
    os.makedirs(LOG_DIR, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
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
# LOGGING FUNCTION
# =========================

def log_event(packet, prediction, action):
    """Log firewall decisions safely"""

    if not isinstance(packet, dict):
        return

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        INSERT INTO logs VALUES (?,?,?,?,?,?,?,?,?)
    """, (
        packet.get("timestamp"),
        packet.get("src_ip"),
        packet.get("dst_ip"),
        packet.get("protocol"),
        packet.get("src_port"),
        packet.get("dst_port"),
        packet.get("length"),
        prediction,
        action
    ))

    conn.commit()
    conn.close()

# =========================
# FIREWALL BLOCKING
# =========================

def block_ip(ip):
    """Block IP using Windows Firewall"""
    if not ip:
        return

    if platform.system() == "Windows":
        cmd = (
            f'netsh advfirewall firewall add rule '
            f'name="AI_Block_{ip}" dir=in action=block remoteip={ip}'
        )
        os.system(cmd)
        print(f"[BLOCKED] {ip}")
