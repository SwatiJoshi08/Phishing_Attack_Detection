import ipaddress
import logging
import time
import re
import requests
from collections import deque
from threading import Thread, Lock, Event
from scapy.all import sniff, IP, TCP, UDP, Raw
import torch
from nlp_pipeline import classify_text
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# ========== Configuration ==========
ABUSEIPDB_API_KEY = "your_api_key_here"  # Replace with your actual API key
TRUSTED_PATTERNS = [
    r"google\.com", 
    r"microsoft\.com",
    r"amazonaws\.com",
    r"windowsupdate\.com"
]
MIN_MODEL_INTERVAL = 0.1  # Minimum delay between model inferences (seconds)
MAX_PAYLOAD_SIZE = 5000   # Maximum payload size to analyze (bytes)

# ========== Logging Setup ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('PacketSniffer')

# ========== Model Loading ==========
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
logger.info(f"Using device: {device}")

try:
    tokenizer = AutoTokenizer.from_pretrained("./phishing_model")
    model = AutoModelForSequenceClassification.from_pretrained("./phishing_model").to(device)
    model.eval()
    # Warmup
    with torch.no_grad():
        _ = model(torch.zeros((1, 10), dtype=torch.long, device=device))
except Exception as e:
    logger.error(f"Model loading failed: {e}")
    raise

# ========== Global State ==========
packet_log = deque(maxlen=1000)
dpi_alerts = deque(maxlen=500)
blocked_ip_info = {}
blocked_ips = set()
whitelist_ips = set()
blacklist_ips = set()
LAST_MODEL_CHECK = 0

# Threading Locks
packet_log_lock = Lock()
dpi_alerts_lock = Lock()
blocked_ips_lock = Lock()
whitelist_lock = Lock()
blacklist_lock = Lock()
sniffer_thread_lock = Lock()

# Sniffer Control
sniffer_thread = None
sniffer_running = False
block_callback = None

# ========== Helper Functions ==========
def check_abuseipdb(ip):
    """Check IP reputation using AbuseIPDB API"""
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=2
        )
        data = response.json()
        return data.get('data', {}).get('abuseConfidenceScore', 0)
    except Exception as e:
        logger.error(f"AbuseIPDB check failed: {e}")
        return 0

def is_valid_ip(ip):
    """Validate IP address format"""
    try:
        ip_part = ip.split(':')[0] if ':' in ip else ip
        ipaddress.ip_address(ip_part)
        return True
    except ValueError:
        return False

def update_whitelist_ips(ips):
    """Update the whitelist IP set"""
    global whitelist_ips
    with whitelist_lock:
        whitelist_ips = {ip for ip in ips if is_valid_ip(ip)}

def update_blacklist_ips(ips):
    """Update the blacklist IP set"""
    global blacklist_ips
    with blacklist_lock:
        blacklist_ips = {ip for ip in ips if is_valid_ip(ip)}

def register_block_callback(callback):
    """Register callback for blocking events"""
    global block_callback
    block_callback = callback

def block_ip(ip):
    """Block an IP address and log the action"""
    if not is_valid_ip(ip):
        return False
        
    try:
        if ipaddress.ip_address(ip).is_private:
            return False
    except ValueError:
        return False

    with blocked_ips_lock, blacklist_lock:
        if ip not in blocked_ips:
            logger.warning(f"Blocking IP: {ip}")
            blocked_ips.add(ip)
            blacklist_ips.add(ip)
            
            blocked_ip_info[ip] = {
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                'reason': 'phishing_content',
                'source': 'auto_block'
            }
            
            if block_callback:
                try:
                    block_callback(ip)
                except Exception as e:
                    logger.error(f"Block callback failed: {e}")
            return True
    return False

def run_phishing_model(payload_text):
    """Run phishing detection model on payload"""
    global LAST_MODEL_CHECK

    # Skip small or non-text payloads
    if len(payload_text) < 20 or not any(c.isprintable() for c in payload_text[:100]):
        return ("safe", 0.0)

    # Rate limiting
    now = time.time()
    if now - LAST_MODEL_CHECK < MIN_MODEL_INTERVAL:
        time.sleep(MIN_MODEL_INTERVAL - (now - LAST_MODEL_CHECK))

    try:
        inputs = tokenizer(
            payload_text, 
            return_tensors="pt", 
            truncation=True, 
            max_length=512
        ).to(device)
        
        with torch.no_grad():
            outputs = model(**inputs)

        prob = torch.nn.functional.softmax(outputs.logits, dim=-1)[0][1].item()
        LAST_MODEL_CHECK = time.time()
        return ("phishing" if prob >= 0.7 else "safe", prob)
    except Exception as e:
        logger.error(f"Model inference error: {e}")
        return ("safe", 0.0)

# ========== Packet Processing ==========
def get_protocol_details(pkt):
    """Extract protocol and port information from packet"""
    proto = "OTHER"
    sport = dport = ""
    
    if pkt.haslayer(TCP):
        proto = "TCP"
        sport = f":{pkt[TCP].sport}"
        dport = f":{pkt[TCP].dport}"
        
        # Detect common application protocols
        if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
            proto = "HTTP"
        elif pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
            proto = "HTTPS"
        elif pkt[TCP].dport == 25 or pkt[TCP].sport == 25:
            proto = "SMTP"
        elif pkt[TCP].dport == 53 or pkt[TCP].sport == 53:
            proto = "DNS"
            
    elif pkt.haslayer(UDP):
        proto = "UDP"
        sport = f":{pkt[UDP].sport}"
        dport = f":{pkt[UDP].dport}"
        if pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
            proto = "DNS"
    
    return proto, sport, dport

def process_packet(pkt):
    """Main packet processing function with enhanced DPI"""
    if not pkt.haslayer(IP):
        return None

    try:
        # Basic packet information
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        timestamp = time.time()
        
        # Skip private IPs
        if ipaddress.ip_address(src_ip).is_private:
            return None

        # Get protocol details
        proto, sport, dport = get_protocol_details(pkt)
        
        # Check IP reputation
        abuse_score = check_abuseipdb(src_ip) if src_ip not in whitelist_ips else 0
        if abuse_score > 85:  # Auto-block high-risk IPs
            block_ip(src_ip)
            return None

        # Create packet info tuple
        packet_info = (
            timestamp,
            time.strftime("%H:%M:%S"),
            proto,
            src_ip,
            dst_ip,
            abuse_score if abuse_score > 0 else None,
            False,  # Initially not flagged
            None,    # Add phishing probability
            []       # Add suspicious keywords
        )
        # Add to packet log
        with packet_log_lock:
            packet_log.append(packet_info)

        # Deep Packet Inspection
        if pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode(errors='ignore').strip()
                
                # Skip small or binary payloads
                if len(payload) < 20 or not any(c.isprintable() for c in payload[:100]):
                    return packet_info
                
                # Whitelist trusted patterns
                if any(re.search(pattern, payload, re.IGNORECASE) for pattern in TRUSTED_PATTERNS):
                    return packet_info
                
                # Protocol-specific processing
                if proto == "HTTP" and "\r\n\r\n" in payload:
                    payload = payload.split("\r\n\r\n")[-1]  # Get body only
                elif proto in ["DNS", "SSH"]:
                    return packet_info  # Skip binary protocols
                
                # Run phishing detection
                result = classify_text(payload[:MAX_PAYLOAD_SIZE])
                if isinstance(result, tuple) and len(result) == 2:
                     phishing_prob, suspicious_keywords = result
                else:
                    phishing_prob, suspicious_keywords = 0.0, []

                
                # Update packet info with analysis results
                packet_info = (
                    packet_info[0],  # timestamp
                    packet_info[1],  # formatted time
                    packet_info[2],  # proto
                    packet_info[3],  # src_ip
                    packet_info[4],  # dst_ip
                    max(abuse_score if abuse_score > 0 else 0, int(phishing_prob * 100)),  # combined score
                    phishing_prob > 0.8,  # flagged if high probability
                    phishing_prob,  # phishing probability
                    suspicious_keywords  # suspicious keywords
                )
                
                # Update in log
                with packet_log_lock:
                    if packet_log and packet_log[-1][0] == timestamp:
                        packet_log[-1] = packet_info
                
                # Generate alert if above threshold
                if phishing_prob > 0.7:
                    severity = "HIGH" if phishing_prob >= 0.9 or abuse_score > 70 else "MEDIUM"
                    
                    # Create detailed alert message
                    alert_msg = (
                        f"{packet_info[1]}|{proto}|{severity}|"
                        f"{src_ip}{sport}→{dst_ip}{dport}|"
                        f"Phishing:{phishing_prob:.2f}|"
                        f"Keywords:{','.join(suspicious_keywords[:3])}"
                    )
                    
                    with dpi_alerts_lock:
                        dpi_alerts.append(alert_msg)
                    
                    # Auto-block high severity
                    if severity == "HIGH" and src_ip not in blacklist_ips:
                        block_ip(src_ip)
                
                return packet_info
                
            except Exception as e:
                logger.error(f"Payload processing error: {e}")
                return packet_info
                
        return packet_info
        
    except Exception as e:
        logger.error(f"Packet processing error: {e}")
        return None

# ========== Sniffing Thread ==========
def sniff_thread(iface, stop_event):
    global sniffer_running
    logger.info(f"Starting sniffer on {iface}")
    
    def should_stop():
        return stop_event.is_set()

    try:
        while not should_stop():
            try:
                sniff(
                    filter="(tcp or udp) and (len > 40)",
                    iface=iface,
                    prn=process_packet,
                    store=False,
                    timeout=1,
                    stop_filter=lambda _: should_stop()
                )
            except Exception as e:
                logger.error(f"Sniffing error (will retry): {e}")
                if not should_stop():
                    time.sleep(1)
                    
    except Exception as e:
        logger.error(f"Sniffer thread error: {e}")
    finally:
        sniffer_running = False
        logger.info("Sniffer thread stopped")

# ========== Sniffer Control ==========
def start_in_background(whitelist, blacklist, iface="Wi-Fi", stop_event=None):
    global sniffer_thread, sniffer_running
    
    # Clean up any existing thread
    stop_sniffer()

    update_whitelist_ips(whitelist)
    update_blacklist_ips(blacklist)

    with sniffer_thread_lock:
        if sniffer_running:
            return False

        sniffer_running = True
        sniffer_thread = Thread(
            target=sniff_thread,
            args=(iface, stop_event if stop_event else Event()),
            daemon=True,
            name=f"PacketSniffer_{iface}"
        )
        sniffer_thread.start()
        return True

def stop_sniffer():
    global sniffer_running, sniffer_thread
    
    with sniffer_thread_lock:
        if not sniffer_running:
            return True

        sniffer_running = False
        if sniffer_thread:
            try:
                if hasattr(sniffer_thread, '_stop_event'):
                    sniffer_thread._stop_event.set()
                sniffer_thread.join(timeout=2)
                if sniffer_thread.is_alive():
                    logger.warning("Forcing thread termination")
            except Exception as e:
                logger.error(f"Error stopping thread: {e}")
            finally:
                sniffer_thread = None
    return True
# ========== Utility Functions ==========
def get_alerts():
    with dpi_alerts_lock:
        alerts = list(dpi_alerts)
        dpi_alerts.clear()
    return alerts

def get_blocked_ip_info():
    with blocked_ips_lock:
        return dict(blocked_ip_info)

def clear_blocked_ip_info():
    with blocked_ips_lock:
        blocked_ips.clear()
        blocked_ip_info.clear()