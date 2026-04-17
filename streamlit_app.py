import streamlit as st
import sqlite3
import pandas as pd
import time
import os

# Allow massive scrolling without breaking Dataframe styler
pd.set_option("styler.render.max_elements", 10_000_000)

st.set_page_config(
    page_title="Enterprise Firewall Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Initialize Session State for Live Capturing Toggle
if 'auto_refresh' not in st.session_state:
    st.session_state.auto_refresh = True

def toggle_refresh():
    st.session_state.auto_refresh = not st.session_state.auto_refresh

st.markdown("""
<style>
    /* Premium Cybersecurity Light Theme */
    .stApp {
        background-color: #ffffff;
        color: #1e293b;
        font-family: 'Inter', '-apple-system', 'Segoe UI', Roboto, sans-serif;
    }
    
    /* Elegant Hero Banner */
    .hero-container {
        padding: 2rem 2.5rem;
        background: linear-gradient(135deg, #f8fafc 0%, #ffffff 100%);
        border-radius: 12px;
        border-left: 6px solid #2563eb;
        border: 1px solid #e2e8f0;
        margin-bottom: 2rem;
        box-shadow: 0 4px 15px rgba(0,0,0,0.03);
    }
    .hero-title {
        color: #0f172a;
        font-size: 32px;
        font-weight: 700;
        margin-bottom: 0.5rem;
        letter-spacing: -0.5px;
    }
    .hero-subtitle {
        color: #64748b;
        font-size: 16px;
        font-weight: 500;
    }
    
    /* Elegant KPI Metrics */
    div[data-testid="stMetric"] {
        background-color: #ffffff;
        padding: 1.5rem;
        border-radius: 12px;
        border: 1px solid #e2e8f0;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.04);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    div[data-testid="stMetric"]:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 16px rgba(0, 0, 0, 0.08);
    }
    [data-testid="stMetricValue"] {
        color: #0f172a !important;
        font-size: 2.5rem !important;
        font-weight: 700 !important;
    }
    [data-testid="stMetricLabel"] {
        color: #64748b !important;
        font-size: 0.95rem !important;
        font-weight: 600 !important;
        text-transform: uppercase;
        letter-spacing: 0.8px;
    }
    
    /* Spacing fixes for section headers */
    .section-title {
        color: #1e293b;
        font-size: 1.35rem;
        font-weight: 600;
        margin-bottom: 1.25rem;
        margin-top: 2rem;
        border-bottom: 2px solid #f1f5f9;
        padding-bottom: 0.5rem;
    }
    
    /* Subtle container shadow for the DataFrame space */
    div[data-testid="stDataFrame"] > div {
        border-radius: 12px !important;
        box-shadow: 0 4px 12px rgba(15, 23, 42, 0.05);
        border: 1px solid #e2e8f0;
        background-color: #ffffff;
    }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero-container">
    <div class="hero-title">🛡️ Global Threat Intelligence Firewall</div>
    <div class="hero-subtitle">Real-Time Autonomous Packet Inspection & Mitigation Operations Center</div>
</div>
""", unsafe_allow_html=True)

placeholder = st.empty()

db_path = "../logs/firewall_logs.db"

with placeholder.container():
    try:
        if not os.path.exists(db_path):
            st.warning("⚠️ Awaiting firewall initialization... No logs detected yet.")
            st.stop()
            
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # 1. Backend Processing: Perform all mathematical counts directly in the database engine (SQL)
        cursor.execute("SELECT COUNT(*) FROM logs")
        total_packets = cursor.fetchone()[0]
        
        if total_packets == 0:
            st.info("System Online. Monitoring active network interfaces...")
            conn.close()
        else:
            # Get threat metrics via SQL to entirely bypass loading frontend data calculation
            cursor.execute("SELECT COUNT(*) FROM logs WHERE label LIKE '%malic%'")
            malicious_count = cursor.fetchone()[0]
            
            # Dashboard KPI Row
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric(label="Total Packets Inspected", value=f"{total_packets:,}")
            with col2:
                st.metric(label="Threats Blocked", value=f"{malicious_count:,}")
            with col3:
                status = "🟢 Secure" if malicious_count == 0 else "🔴 Active Defense"
                st.metric(label="System Status", value=status)
                
            col_t, col_b = st.columns([6, 1])
            with col_t:
                st.markdown('<div class="section-title">📡 Live Capture History</div>', unsafe_allow_html=True)
            with col_b:
                st.markdown("<div style='margin-top: 2rem;'></div>", unsafe_allow_html=True)
                if st.session_state.auto_refresh:
                    st.button("⏸️ Stop Capturing", on_click=toggle_refresh, use_container_width=True)
                else:
                    st.button("▶️ Resume Capturing", on_click=toggle_refresh, type="primary", use_container_width=True)
            
            # 2. Backend Processing: Format columns, mappings, and sorting inside the database
            # We enforce a limit of 5,000 most recent rows to ensure instant UI loads without hanging,
            # while fully preserving a large scrollable history for users.
            query = '''
            SELECT 
                datetime(timestamp, 'unixepoch', 'localtime') as [Timestamp],
                src_ip as [Source IP],
                dst_ip as [Destination IP],
                protocol as [Protocol],
                length as [Packet Length],
                CASE 
                    WHEN label LIKE '%malic%' THEN 'Malicious'
                    ELSE 'Benign' 
                END as [Label],
                CASE 
                    WHEN action LIKE '%block%' THEN 'Blocked'
                    ELSE 'Allowed' 
                END as [Action]
            FROM logs
            ORDER BY timestamp DESC
            LIMIT 5000
            '''
            display_df = pd.read_sql(query, conn)
            conn.close()
            
            # 3. Precise Visual Highlighting Requirements (Light Theme Adapted)
            def highlight_threats(row):
                if row['Label'] == 'Malicious':
                    # Malicious: brilliant red background for maximum visibility in light mode, dark red text
                    return ['background-color: #fee2e2; color: #b91c1c; font-weight: 600; border-bottom: 2px solid #fca5a5;'] * len(row)
                else:
                    # Benign: Clean white row with light gray text
                    return ['background-color: #ffffff; color: #475569; border-bottom: 1px solid #f1f5f9;'] * len(row)
                    
            st.dataframe(
                display_df.style.apply(highlight_threats, axis=1),
                use_container_width=True,
                height=650, # High container perfectly suited for endless scrolling
                hide_index=True
            )
            
    except Exception as e:
        st.error(f"Connecting to live data stream... (Details: {e})")

# Real-Time UI Behavior looping smoothly
if st.session_state.auto_refresh:
    time.sleep(1.5)
    st.rerun()
