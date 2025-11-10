import streamlit as st
import re
import requests
import pandas as pd 
import time
import os
import ipaddress
import logging
import sys
import asyncio
import torch
import uuid
from datetime import datetime
from collections import defaultdict
from streamlit_autorefresh import st_autorefresh
from scapy.all import get_if_list
from queue import Queue
from threading import Event
from nlp_pipeline import (
    classify_text, analyze_ner, analyze_sentiment,
    set_sender_whitelist, is_sender_trusted
)
from packet_sniffer import (
    start_in_background, packet_log, register_block_callback, block_ip,
    get_blocked_ip_info, clear_blocked_ip_info, update_whitelist_ips, update_blacklist_ips,
    dpi_alerts, dpi_alerts_lock, stop_sniffer, packet_log_lock
)
from packet_sniffer import blocked_ips 

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),  # Output to console
        logging.FileHandler('phishing_detection.log')  # Output to file
    ]
)
logger = logging.getLogger(__name__)

if sys.platform == "win32" and sys.version_info >= (3, 8):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# Initialize session state variables
if "alerts" not in st.session_state:
    st.session_state["alerts"] = []
if "active_tab" not in st.session_state:
    st.session_state["active_tab"] = "Real-time DPI"
if "session_id" not in st.session_state:
    st.session_state["session_id"] = str(uuid.uuid4())

LAST_IP_CHECK_TIME = 0
MIN_CHECK_INTERVAL = 0.5

# Initialize other session state variables
if 'blacklist_ips' not in st.session_state:
    st.session_state.blacklist_ips = []
if 'whitelist_ips' not in st.session_state:
    st.session_state.whitelist_ips = []
if 'sniffer_stop_event' not in st.session_state:
    st.session_state.sniffer_stop_event = None
if 'sniffer_started' not in st.session_state:
    st.session_state.sniffer_started = False

# ========================== CONFIGURATION ==========================
INTERFACE_GUID = "{8B9EAA08-6502-407C-ADB2-229BD7A8E1B6}"
INTERFACE_NAME = f"\\Device\\NPF_{INTERFACE_GUID}"
try:
    get_if_list().index(INTERFACE_NAME)
except ValueError:
    INTERFACE_NAME = get_if_list()[0]  # fallback to first available

WHITELIST_EMAIL_FILE = "whitelist.txt"
WHITELIST_IP_FILE = "whitelist_ips.txt"
BLACKLIST_IP_FILE = "blacklist_ips.txt"

st.set_page_config(page_title="Phishing Attack Detection", layout="wide")
st_autorefresh(interval=2000, limit=None, key="packet_refresh")

# ========================== STATE INIT ==========================
def init_state():
    defaults = {
        "whitelist": [], 
        "whitelist_ips": [], 
        "blacklist_ips": [], 
        "blocked_ips": [],
        "phishing_prob": 0.0, 
        "suspicious_keywords": [], 
        "verdict": "LEGITIMATE",
        "trusted_sender_msg": "", 
        "entities": [], 
        "sentiment": {},
        "highlighted_message": "", 
        "analysis_done": False, 
        "user_actions": [],
        "sniffer_started": False, 
        "sniffer_queue": None,
        "sniffer_stop_event": None
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

# Call this early in your script
init_state()

if 'recent_packets' not in st.session_state:
    st.session_state['recent_packets'] = []
    
current_time = time.time()
st.session_state["recent_packets"] = [
    pkt for pkt in st.session_state.get("recent_packets", [])
    if current_time - pkt[0] <= 5
]

# ========================== UTILS ==========================
def log_user_action(action, details=None):
    """Enhanced user action logging with timestamp and details"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        "timestamp": timestamp,
        "action": action,
        "details": details or {},
        "active_tab": st.session_state.get("active_tab", "Unknown"),
        "session_id": st.session_state.get("session_id")
    }
    
    # Add to session state
    if "user_actions" not in st.session_state:
        st.session_state["user_actions"] = []
    st.session_state["user_actions"].append(log_entry)
    
    # Also write to log file with UTF-8 encoding
    with open("user_behavior.log", "a", encoding='utf-8') as f:  # Added encoding parameter
        f.write(f"{timestamp} - {action}\n")
        if details:
            f.write(f"Details: {str(details)}\n")
    
    logger.info(f"User Action: {action}", extra=log_entry)

def track_tab_change(new_tab):
    """Track tab changes and log only when the tab actually changes"""
    if "last_tab" not in st.session_state:
        st.session_state.last_tab = new_tab
    
    if st.session_state.last_tab != new_tab:
        log_user_action(f"Switched from {st.session_state.last_tab} to {new_tab}")
        st.session_state.last_tab = new_tab

def get_ip_risk_level(ip):
    """Classify IP risk level, handling port numbers if present"""
    base_ip = ip.split(':')[0] if ':' in ip else ip
    
    try:
        if ipaddress.ip_address(base_ip).is_private:
            return "safe"
    except ValueError:
        return "unknown"
    
    if base_ip in st.session_state["blacklist_ips"]:
        return "danger"
        
    if base_ip in st.session_state["whitelist_ips"]:
        return "safe"
    
    if base_ip in st.session_state["blocked_ips"]:
        return "danger"
    
    abuse_score = get_cached_ip_reputation(base_ip)
    if abuse_score is None:
        return "unknown"
    
    if abuse_score >= 70:
        return "danger"
    elif abuse_score >= 40:
        return "warning"
    return "safe"

def format_packet_line(pkt_time, proto, src_ip, dst_ip, abuse_score=None, flagged=False, 
                      phishing_prob=None, keywords=None, sentiment=None):
    src_risk = get_ip_risk_level(src_ip)
    is_blocked = src_ip in st.session_state.get("blocked_ips", [])
    
    if is_blocked:
        status = "⛔ BLOCKED"
        color = "#ff0000"
        icon = "🔴"
    elif src_risk == "danger":
        status = "⚠️ HIGH RISK"
        color = "#ff4b4b"
        icon = "🔴"
    elif src_risk == "warning":
        status = "⚠️ SUSPICIOUS" 
        color = "#ffa500"
        icon = "🟡"
    elif src_risk == "safe":
        status = "✓ SAFE"
        color = "#2ecc71"
        icon = "🟢"
    else:
        status = "? UNKNOWN"
        color = "#cccccc"
        icon = "⚪"
    
    extra_info = ""
    if phishing_prob is not None:
        extra_info += f" | Phish: {phishing_prob*100:.1f}%"
    if keywords:
        extra_info += f" | Keywords: {','.join(keywords[:2])}"
    
    return (
        f"<span style='color:{color}; font-weight:bold;'>"
        f"{pkt_time} | {proto} | {icon} {src_ip} ({status}) → 🟢 {dst_ip}"
        f"{extra_info}</span>"
    )
    
def save_blacklist():
    with open(BLACKLIST_IP_FILE, "w") as f:
        f.writelines(ip + "\n" for ip in st.session_state["blacklist_ips"])

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def highlight_keywords(text, keywords):
    for kw in keywords:
        regex = re.compile(rf"(\b{re.escape(kw)}\b)", re.IGNORECASE)
        text = regex.sub(r'<mark>\1</mark>', text)
    return text

def notify_blocked_ip(ip):
    try:
        base_ip = ip.split(':')[0] if ':' in ip else ip
        
        if not is_valid_ip(base_ip) or ipaddress.ip_address(base_ip).is_private:
            print(f"Skipping invalid/private IP: {ip}")
            return
            
        print(f"Attempting to block IP: {base_ip}")
        
        if base_ip not in st.session_state["blacklist_ips"]:
            st.session_state["blacklist_ips"].append(base_ip)
            st.session_state["blocked_ips"].append(base_ip)
            save_blacklist()
            update_blacklist_ips(st.session_state["blacklist_ips"])
            print(f"Added to blacklist: {base_ip}") 
            
        log_user_action(f"Blocked IP {base_ip}")
        
    except Exception as e:
        print(f"Error blocking IP {ip}: {e}")
        st.error(f"Failed to block {ip}: {str(e)}")

# ========================== AbuseIPDB ==========================
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
if not ABUSEIPDB_API_KEY:
    st.error("AbuseIPDB API key not set. Use: export ABUSEIPDB_API_KEY=your_key")
    st.stop()

def check_ip_reputation(ip):
    global LAST_IP_CHECK_TIME
    
    base_ip = ip.split(':')[0] if ':' in ip else ip
    
    now = time.time()
    if now - LAST_IP_CHECK_TIME < MIN_CHECK_INTERVAL:
        time.sleep(MIN_CHECK_INTERVAL - (now - LAST_IP_CHECK_TIME))
    
    try:
        print(f"Checking reputation for: {base_ip}")
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Accept": "application/json", "Key": ABUSEIPDB_API_KEY},
            params={"ipAddress": base_ip, "maxAgeInDays": 90},
            timeout=5
        )
        LAST_IP_CHECK_TIME = time.time()
        
        if response.status_code == 200:
            data = response.json()
            return data['data'].get('abuseConfidenceScore', 0)
    except Exception as e:
        print(f"[Reputation Error] {e}")
    return None

@st.cache_data(ttl=3600)
def get_cached_ip_reputation(ip):
    if not is_valid_ip(ip) or ip in st.session_state["whitelist_ips"]:
        return None
    try:
        return check_ip_reputation(ip)
    except Exception as e:
        st.error(f"Error checking IP reputation: {str(e)}")
        return None

# ========================== Heuristic Detection ==========================
def heuristic_ip_flag(ip, proto, timestamp):
    if not is_valid_ip(ip) or ip in st.session_state["whitelist_ips"]:
        return False
        
    key = f"{ip}_{proto}"
    if key not in st.session_state:
        st.session_state[key] = []
    
    st.session_state[key].append(timestamp)
    st.session_state[key] = [t for t in st.session_state[key] if t > timestamp - 60]
    
    thresholds = {
        "TCP": 100,
        "UDP": 50,
        "OTHER": 30
    }
    
    return len(st.session_state[key]) > thresholds.get(proto, 30)

# ========================== Load Lists ==========================
def load_list_from_file(filename):
    try:
        with open(filename, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []

# Load all whitelists/blacklists into session
for k, f, update_fn in [
    ("whitelist", WHITELIST_EMAIL_FILE, set_sender_whitelist),
    ("whitelist_ips", WHITELIST_IP_FILE, update_whitelist_ips),
    ("blacklist_ips", BLACKLIST_IP_FILE, update_blacklist_ips)
]:
    if not st.session_state[k]:
        values = load_list_from_file(f)
        st.session_state[k] = values
        update_fn(values)

# Mirror blacklist to blocked IPs
for ip in st.session_state["blacklist_ips"]:
    if ip not in st.session_state["blocked_ips"]:
        st.session_state["blocked_ips"].append(ip)

# ========================== Start Sniffer on First Load ==========================
if not st.session_state["sniffer_started"]:
    with st.spinner("Initializing packet sniffer..."):
        start_in_background(st.session_state["whitelist_ips"], st.session_state["blacklist_ips"], iface=INTERFACE_NAME)
    st.session_state["sniffer_started"] = True
    log_user_action("Packet sniffer started")

# ========================== UI ==========================
st.title("🛡️ Phishing Attack Detection Dashboard")

# Track tab changes
def track_tab_change(new_tab):
    if "last_tab" not in st.session_state:
        st.session_state.last_tab = new_tab
    if st.session_state.last_tab != new_tab:
        log_user_action(f"Switched from {st.session_state.last_tab} to {new_tab}")
        st.session_state.last_tab = new_tab

# Create tabs
tab1, tab2, tab3 = st.tabs([
    "✉️ Email Analysis",
    "📡 Network Monitor", 
    "🧠 DPI Alerts"
])

# === Tab 1: Email Analysis ===
with tab1:
    if st.session_state.get("last_tab") != "✉️ Email Analysis":
        track_tab_change("✉️ Email Analysis")
    
    sender_email = st.text_input("Sender Email")
    message = st.text_area("Enter Email Text for Analysis", height=200)

    if st.button("Analyze"):
        log_user_action("Analyze button clicked", {
            "sender": sender_email,
            "message_length": len(message)
        })
        
        if not sender_email.strip() or not message.strip():
            st.warning("Please enter both Sender Email and Email Text.")
        else:
            log_user_action("Analyze button clicked", {
            "sender": sender_email,
            "message_length": len(message)
        })
            domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
            if is_sender_trusted(sender_email) or domain in ["amazon.com", "amazon.in"]:
                st.session_state["phishing_prob"] = 0.0
                st.session_state["suspicious_keywords"] = []
                st.session_state["verdict"] = "LEGITIMATE"
                st.session_state["trusted_sender_msg"] = f"Sender {sender_email} is trusted — marked as Legitimate"
                st.session_state["entities"] = []
                st.session_state["sentiment"] = {}
                st.session_state["highlighted_message"] = message
            else:
                phishing_prob, suspicious_keywords = classify_text(message)
                st.session_state["phishing_prob"] = phishing_prob
                st.session_state["suspicious_keywords"] = suspicious_keywords
                st.session_state["verdict"] = "PHISHING" if phishing_prob > 0.8 else "LEGITIMATE"
                st.session_state["trusted_sender_msg"] = ""
                st.session_state["highlighted_message"] = highlight_keywords(message, suspicious_keywords)
                st.session_state["entities"] = analyze_ner(message)
                st.session_state["sentiment"] = analyze_sentiment(message)

            st.session_state["analysis_done"] = True

    if st.session_state.get("analysis_done", False):
        if st.session_state.get("trusted_sender_msg"):
            st.success(st.session_state["trusted_sender_msg"])

        st.write(f"**Phishing Probability:** {st.session_state['phishing_prob']*100:.2f}%")

        if st.session_state["verdict"] == "LEGITIMATE":
            st.success(f"✔️ Verdict: {st.session_state['verdict']}")
        else:
            st.error(f"⚠️ Verdict: {st.session_state['verdict']}")

        st.markdown("**Message with Suspicious Keywords Highlighted:**")
        st.markdown(st.session_state["highlighted_message"], unsafe_allow_html=True)

        if st.session_state.get("entities"):
            st.markdown("**Named Entities:**")
            for ent, label in st.session_state["entities"]:
                st.write(f"- {ent} ({label})")

        if st.session_state.get("sentiment"):
            st.markdown("**Sentiment Prediction (BERT):**")
            st.write(f"Label: **{st.session_state['sentiment'].get('label', '')}**")
            st.write(f"Confidence: **{st.session_state['sentiment'].get('confidence', '')}**")
            st.markdown("**Sentiment Scores:**")
            st.json(st.session_state["sentiment"])

# === TAB 2: NETWORK MONITOR ===
with tab2:
    if st.session_state.get("last_tab") != "📡 Network Monitor":
        track_tab_change("📡 Network Monitor")
    log_user_action("Viewed Network Monitor")
    
    st.subheader("📡 Real-Time Network Monitor")

    iface_list = get_if_list()
    iface_sel = st.selectbox("🔌 Select Interface", iface_list, index=0, 
                            on_change=lambda: log_user_action("Interface selected", 
                                                           {"interface": iface_sel}))

    st.markdown("""
    **Risk Legend:**
    - 🔴 <span style='color:#ff4b4b;'>RED</span>: Blocked/Spam IP (AbuseScore ≥70)
    - 🟡 <span style='color:#ffa500;'>YELLOW</span>: Suspicious IP (40 ≤ AbuseScore < 70)
    - 🟢 <span style='color:#2ecc71;'>GREEN</span>: Safe/Whitelisted IP
    - ⚪ <span style='color:#cccccc;'>GRAY</span>: Unknown reputation
    """, unsafe_allow_html=True)

    # Sniffer Status
    with st.status("Packet Sniffer Status", expanded=False) as status:
        if st.session_state.get("sniffer_started"):
            status.update(label="✅ Packet sniffer is running", state="complete")
        else:
            status.update(label="❌ Packet sniffer not running", state="error")

    st.markdown("---")
    st.subheader("🧾 Captured Packets")

    with packet_log_lock:
        try:
            recent_packets = list(packet_log)[-100:]
        except Exception as e:
            logger.error(f"Packet log access error: {e}")
            recent_packets = []

    if not recent_packets:
        st.info("No network packets captured yet.")
    else:
        packet_groups = defaultdict(list)
        for packet in recent_packets:
            try:
                if isinstance(packet, tuple) and len(packet) >= 5:
                    src_ip = packet[3]
                    packet_groups[src_ip].append(packet)
            except Exception as e:
                logger.error(f"Packet grouping error: {e}")

        for src_ip, packets in packet_groups.items():
            with st.expander(f"Packets from {src_ip}", expanded=False):
                for packet in reversed(packets):
                    try:
            # New packet format handling code
                        if len(packet) == 11:  # Full format with all fields
                            timestamp, _, proto, src_ip, dst_ip, abuse_score, flagged, phishing_prob, keywords, sentiment, _ = packet
                        elif len(packet) == 9:  # Basic format without sentiment/entities
                            timestamp, _, proto, src_ip, dst_ip, abuse_score, flagged, phishing_prob, keywords = packet
                            sentiment = None
                        else:
                            logger.error(f"Unexpected packet format with {len(packet)} fields")
                            continue
            
                        pkt_time = time.strftime("%H:%M:%S", time.localtime(timestamp))
                        line = format_packet_line(
                            pkt_time, proto, src_ip, dst_ip, 
                            abuse_score, flagged, phishing_prob, 
                            keywords, sentiment
                        )
                        st.markdown(line, unsafe_allow_html=True)
            
                        if (abuse_score and abuse_score >= 70) or flagged:
                            if src_ip not in st.session_state["blocked_ips"]:
                                notify_blocked_ip(src_ip)
                                time.sleep(0.5)
                                st.rerun()
                    
                    except Exception as e:
                        logger.error(f"Packet render error: {e}")
                        
                        pkt_time = time.strftime("%H:%M:%S", time.localtime(timestamp))
                        
                        if abuse_score is None:
                            abuse_score = get_cached_ip_reputation(src_ip)
                        
                        line = format_packet_line(
                            pkt_time, proto, src_ip, dst_ip, 
                            abuse_score, flagged, phishing_prob, 
                            keywords, sentiment
                        )
                        st.markdown(line, unsafe_allow_html=True)
                        
                        if (abuse_score and abuse_score >= 70) or flagged:
                            if src_ip not in st.session_state["blocked_ips"]:
                                notify_blocked_ip(src_ip)
                                time.sleep(0.5)
                                st.rerun()
                                
                    except Exception as e:
                        logger.error(f"Packet render error: {e}")

    st.markdown("---")
    st.subheader("⛔ Blocked IPs")
    
    blocked_info = get_blocked_ip_info()
    session_blocked = st.session_state.get("blocked_ips", [])
    all_blocked = set(blocked_info.keys()).union(set(session_blocked))
    
    if all_blocked:
        for ip in all_blocked:
            col1, col2 = st.columns([3, 2])
            with col1:
                st.write(f"- {ip}")
            with col2:
                timestamp = blocked_info.get(ip, {}).get('timestamp', 'Recently blocked')
                st.caption(f"Blocked at: {timestamp}")
    else:
        st.info("No IPs have been blocked yet.")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔄 Clear Packet Log"):
            log_user_action("Cleared packet log")
            with packet_log_lock:
                packet_log.clear()
            st.toast("Packet log cleared", icon="✅")

    with col2:
        if st.button("🧹 Clear Blocked IPs"):
            log_user_action("Cleared blocked IPs", {
                "count": len(st.session_state.get("blocked_ips", []))
            })
            st.session_state["blocked_ips"] = []
            st.session_state["blacklist_ips"] = []
            update_blacklist_ips([])
            save_blacklist()
            clear_blocked_ip_info()
            blocked_ips.clear()
            st.toast("Blocked IP list cleared", icon="✅")
            st.rerun()
# === TAB 3: DPI Packet Inspection ===
with tab3:
    track_tab_change("🧠 DPI Alerts")
    
    st.header("📊 Deep Packet Inspection")
    st.markdown("""
    <style>
        .packet-info {
            font-family: monospace;
            margin: 0.5em 0;
            padding: 0.5em;
            border-radius: 0.25rem;
            background-color: #f8f9fa;
        }
        .payload {
            max-height: 200px;
            overflow-y: auto;
            background-color: #f0f0f0;
            padding: 0.5em;
            border-radius: 0.25rem;
            font-family: monospace;
            white-space: pre-wrap;
        }
        .suspicious {
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 0.5em;
        }
        .high-risk {
            background-color: #f8d7da;
            border-left: 4px solid #dc3545;
            padding: 0.5em;
        }
        mark {
            background-color: #ffeb3b;
            padding: 0.1em;
        }
    </style>
    """, unsafe_allow_html=True)

    with dpi_alerts_lock:
        recent_alerts = list(dpi_alerts)[-100:]

    if not recent_alerts:
        st.info("No DPI alerts detected yet. Waiting for network traffic...")
    else:
        for alert in reversed(recent_alerts):
            try:
                parts = alert.split("|")
                if len(parts) >= 4:
                    # Extract basic info
                    time_str = parts[0].strip()
                    proto = parts[1].strip()
                    severity = parts[2].strip()
                    connection = parts[3].strip()
                    
                    # Determine alert style based on severity
                    alert_style = "packet-info"
                    if severity == "HIGH":
                        alert_style = "high-risk"
                    elif severity == "MEDIUM":
                        alert_style = "suspicious"
                    
                    # Create expandable alert
                    with st.expander(f"{time_str} - {severity} severity alert ({proto})", expanded=False):
                        st.markdown(f"""
                        <div class="{alert_style}">
                            <strong>🕒 Time:</strong> {time_str}<br>
                            <strong>📡 Protocol:</strong> {proto}<br>
                            <strong>🔗 Connection:</strong> {connection}<br>
                            <strong>⚠️ Severity:</strong> {severity}
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Parse and display all alert details
                        details = {}
                        for part in parts[4:]:
                            if ":" in part:
                                key, value = part.split(":", 1)
                                details[key.strip()] = value.strip()
                        
                        # Display analysis results
                        if "Phishing" in details:
                            st.markdown(f"**Phishing Probability:** {float(details['Phishing'])*100:.1f}%")
                        
                        if "Keywords" in details and details['Keywords']:
                            keywords = details['Keywords'].split(",")
                            st.markdown("**Suspicious Keywords:**")
                            st.write(", ".join([f"`{kw}`" for kw in keywords if kw]))
                        
                        # Display payload with highlighted keywords if available
                        if "Len" in details and int(details['Len']) > 0:
                            payload = ""
                            if "Payload" in details:
                                payload = details["Payload"]
                            elif len(parts) > 5 and ":" in parts[5]:
                                payload = parts[5].split(":", 1)[1]
                            
                            if payload:
                                st.markdown("**Payload Content:**")
                                highlighted = payload
                                if "Keywords" in details:
                                    keywords = details['Keywords'].split(",")
                                    highlighted = highlight_keywords(payload, keywords)
                                st.markdown(f'<div class="payload">{highlighted}</div>', unsafe_allow_html=True)
                        
                        # Add block button for high severity alerts
                        if severity == "HIGH" and "src_ip" in connection:
                            src_ip = connection.split("→")[0].split(":")[0]
                            if st.button(f"⛔ Block {src_ip}", key=f"block_{src_ip}_{time_str}"):
                                notify_blocked_ip(src_ip)
                                st.rerun()
                    
                    st.markdown("---")
                    
            except Exception as e:
                logger.error(f"Error displaying alert: {alert} - {str(e)}")

    # Add controls at the bottom
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Clear DPI Alerts", key="clear_dpi_alerts"):
            log_user_action("Cleared DPI alerts")
            with dpi_alerts_lock:
                dpi_alerts.clear()
            st.rerun()
    
    with col2:
        if st.button("Analyze Recent Traffic", key="analyze_traffic"):
            log_user_action("Analyzed recent traffic")
            with packet_log_lock:
                recent_packets = list(packet_log)[-110:]
            
            suspicious_count = 0
            total_analyzed = 0
            
            for packet in recent_packets:
                if len(packet) >= 7 and packet[6]:  # Check if flagged
                    suspicious_count += 1
                if len(packet) >= 7:
                    total_analyzed += 1
            
            if total_analyzed > 0:
                st.success(f"Analyzed {total_analyzed} packets, found {suspicious_count} suspicious ({suspicious_count/total_analyzed*100:.1f}%)")
            else:
                st.info("No packets available for analysis")