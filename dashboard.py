import streamlit as st
import pandas as pd
import math
import time
from collections import Counter
from sklearn.ensemble import IsolationForest

# --- PAGE SETUP ---
st.set_page_config(page_title="NTRO Threat Monitor", page_icon="🛡️", layout="wide")
st.title("🛡️ NTRO Unidirectional Threat Monitor (LIVE 🔴)")
st.markdown("Real-time passive AI/ML pipeline for detecting zero-day network threats.")
st.markdown("---")

# --- AI BRAIN FUNCTIONS ---
def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_features(website):
    length = len(website)
    vowels = sum(1 for char in website if char in 'aeiou')
    vowel_ratio = vowels / length if length > 0 else 0
    entropy = calculate_entropy(website)
    return [length, vowel_ratio, entropy]

# --- LOAD DATA ---
websites = []
ips = []

with open("clean_dns.txt", "r") as file:
    for line in file:
        cols = line.split()
        if len(cols) == 2:
            ips.append(cols[0])
            websites.append(cols[1])

# --- THREAT C: DGA DETECTION (Machine Learning) ---
X_data = [extract_features(site) for site in websites]
model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
if len(X_data) > 0:
    model.fit(X_data)
    dga_predictions = model.predict(X_data)
else:
    dga_predictions = []

# --- THREAT A: DDoS DETECTION (Flow-Rate Analysis) ---
# Count how many times each IP address appears in our traffic
ip_counts = Counter(ips)
DDOS_THRESHOLD = 50 # If an IP sends more than 50 requests instantly, flag it!

# --- SCOREBOARD UI ---
total_traffic = len(ips)
col1, col2, col3 = st.columns(3)
col1.metric("🌐 Total Flows Analyzed", total_traffic)
col2.metric("🔒 System Status", "ACTIVE - PASSIVE MODE")
col3.metric("⏱️ Refresh Rate", "2.0s")

st.markdown("---")

# --- DISPLAY THREAT A (DDoS) ---
st.markdown("### 💥 Threat A: Volumetric DDoS Alerts")
ddos_list = []
for ip, count in ip_counts.items():
    if count >= DDOS_THRESHOLD:
        ddos_list.append({
            "Attacker IP": ip,
            "Flow Volume": f"{count} packets/sec",
            "Detection Method": "Rate-Limit Exceeded",
            "Severity": "CRITICAL"
        })

if len(ddos_list) > 0:
    st.dataframe(pd.DataFrame(ddos_list), use_container_width=True)
    st.error(f"⚠️ DDOS AVALANCHE DETECTED: {len(ddos_list)} IP(s) exceeding normal flow rates.")
else:
    st.success("✅ Flow rates normal. No DDoS detected.")

# --- DISPLAY THREAT C (DGA) ---
st.markdown("### 🦠 Threat C: DGA Malware Alerts")
dga_list = []
for i in range(len(dga_predictions)):
    if dga_predictions[i] == -1:
        feats = X_data[i]
        dga_list.append({
            "Source IP": ips[i],
            "Malicious Domain": websites[i],
            "Entropy Score": round(feats[2], 2),
            "Confidence": "HIGH (Isolation Forest)"
        })

if len(dga_list) > 0:
    # We use head(5) to only show the top 5 so a DDoS attack doesn't break our screen!
    st.dataframe(pd.DataFrame(dga_list).head(5), use_container_width=True)
    st.warning("⚠️ DGA Beaconing detected. Do not establish return paths.")
else:
    st.success("✅ Network Secure. No DGA anomalies.")

# --- LIVE STREAMING LOOP ---
time.sleep(2)
st.rerun()
