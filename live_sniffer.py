# live_sniffer_geolocate.py (save as live_sniffer.py or new file)
import time
import threading
import requests
import joblib
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# CONFIG
FLASK_ALERT_URL = "http://127.0.0.1:5000/alert"   # Flask endpoint (must be running)
FLOW_TIMEOUT = 10.0   # seconds of inactivity to finalize flow
CAPTURE_IFACE = None  # None for default or "eth0"/"Wi-Fi" etc.
MODEL_PATH = "model.pkl"
GEO_API = "http://ip-api.com/json/{ip}?fields=status,country,city,query"  # ip-api free endpoint
GEO_CACHE = {}  # simple dict cache: ip -> {country, city}

# load model for local scoring
model = joblib.load(MODEL_PATH)
print("Model loaded in sniffer.")

PROTO_MAP = {"tcp":0, "udp":1, "icmp":2}

flows = {}
flows_lock = threading.Lock()

def make_flow_key(pkt):
    if IP not in pkt:
        return None
    ip = pkt[IP]
    sport = dport = 0
    proto = None
    if pkt.haslayer(TCP):
        proto = 'tcp'
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto = 'udp'
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        proto = 'icmp'
    else:
        proto = str(ip.proto)
    # normalize src/dst to string
    return (str(ip.src), str(ip.dst), sport, dport, proto)

def pkt_payload_len(pkt):
    if pkt.haslayer(Raw):
        return len(pkt[Raw].load)
    if IP in pkt:
        ip = pkt[IP]
        if hasattr(ip, 'len') and ip.len:
            return max(0, ip.len - 40)
    return 0

def process_packet(pkt):
    key = make_flow_key(pkt)
    if key is None:
        return
    now = time.time()
    payload = pkt_payload_len(pkt)
    src, dst, sport, dport, proto = key
    pkt_src = pkt[IP].src

    with flows_lock:
        if key not in flows:
            flows[key] = {'start': now, 'last': now, 'src_bytes':0, 'dst_bytes':0, 'src':src, 'dst':dst, 'proto':proto}
        f = flows[key]
        f['last'] = now
        if str(pkt_src) == f['src']:
            f['src_bytes'] += payload
        else:
            f['dst_bytes'] += payload

def geo_lookup(ip):
    """Return (country, city) for IP. Uses simple cache and ip-api.com."""
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    try:
        r = requests.get(GEO_API.format(ip=ip), timeout=3)
        data = r.json()
        if data.get("status") == "success":
            country = data.get("country")
            city = data.get("city")
        else:
            country = None
            city = None
    except Exception:
        country = None
        city = None
    GEO_CACHE[ip] = (country, city)
    return (country, city)

def finalizer_worker():
    while True:
        now = time.time()
        to_send = []
        with flows_lock:
            for k, f in list(flows.items()):
                if now - f['last'] > FLOW_TIMEOUT:
                    to_send.append(f.copy())
                    del flows[k]
        for f in to_send:
            handle_flow(f)
        time.sleep(1.0)

def handle_flow(f):
    duration = max(0.0, f['last'] - f['start'])
    src_bytes = int(f['src_bytes'])
    dst_bytes = int(f['dst_bytes'])
    proto = f['proto']
    proto_val = PROTO_MAP.get(proto, 0)

    # local model scoring
    try:
        X = pd.DataFrame([[duration, src_bytes, dst_bytes, proto_val]],
                         columns=["duration","src_bytes","dst_bytes","protocol_type"])
        pred = int(model.predict(X)[0])
        score = None
        if hasattr(model, "predict_proba"):
            score = float(model.predict_proba(X)[0].max())
        prediction_text = "Threat" if pred == 1 else "Normal"
    except Exception as e:
        pred = None
        score = None
        prediction_text = "Unknown"

    # geo lookup for src and dst (cached)
    src = f['src']
    dst = f['dst']
    src_country, src_city = geo_lookup(src)
    dst_country, dst_city = geo_lookup(dst)

    payload = {
        "src": src,
        "dst": dst,
        "proto": proto,
        "protocol_type": proto_val,
        "duration": duration,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "prediction": prediction_text,
        "score": score,
        "src_country": src_country,
        "src_city": src_city,
        "dst_country": dst_country,
        "dst_city": dst_city
    }

    # POST to Flask
    try:
        r = requests.post(FLASK_ALERT_URL, json=payload, timeout=2)
        if r.status_code == 200:
            print("Posted alert:", src, "->", dst, payload["prediction"], src_country, dst_country)
        else:
            print("Flask returned", r.status_code, r.text)
    except Exception as e:
        print("Failed to post alert:", e)

def main():
    t = threading.Thread(target=finalizer_worker, daemon=True)
    t.start()
    print("Starting capture (CTRL-C to stop).")
    sniff(iface=CAPTURE_IFACE, prn=process_packet, store=False)

if __name__ == "__main__":
    main()
