import streamlit as st
import pandas as pd
import math
import time
from collections import Counter
from sklearn.ensemble import IsolationForest

st.set_page_config(page_title="NTRO Threat Monitor", page_icon="🛡️", layout="wide")
st.title("🛡️ NTRO Unidirectional Threat Monitor (PROD 🔴)")
st.markdown("Enterprise pipeline natively ingesting Zeek network sensors.")
st.markdown("---")

def calculate_entropy(text):
    if not text or text == '-': return 0
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

# --- ENTERPRISE ZEEK PARSER ---
websites = []
ips = []

try:
    with open("dns.log", "r") as file:
        ip_idx = -1
        query_idx = -1
        
        for line in file:
            # Dynamically map columns based on Zeek's header
            if line.startswith("#fields"):
                headers = line.strip().split("\t")
                ip_idx = headers.index("id.orig_h")
                query_idx = headers.index("query")
            
            # Read the actual traffic, skipping comments
            elif not line.startswith("#") and ip_idx != -1 and query_idx != -1:
                cols = line.strip().split("\t")
                if len(cols) > max(ip_idx, query_idx):
                    ip = cols[ip_idx]
                    query = cols[query_idx]
                    
                    # Zeek uses '-' if a query is empty/missing
                    if query != '-':
                        ips.append(ip)
                        websites.append(query)
except FileNotFoundError:
    st.error("Waiting for Zeek sensor to generate dns.log...")

# --- THREAT C: DGA DETECTION ---
X_data = [extract_features(site) for site in websites]
model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
if len(X_data) > 0:
    model.fit(X_data)
    dga_predictions = model.predict(X_data)
else:
    dga_predictions = []

# --- THREAT A: DDoS DETECTION ---
ip_counts = Counter(ips)
DDOS_THRESHOLD = 50

# --- UI RENDERING ---
col1, col2, col3 = st.columns(3)
col1.metric("🌐 Total Flows Analyzed", len(ips))
col2.metric("🔒 Sensor", "Zeek Native Integration")
col3.metric("⏱️ Mode", "Live Streaming")
st.markdown("---")

st.markdown("### 💥 Threat A: Volumetric Alerts")
ddos_list = [{"Attacker IP": ip, "Flow Volume": count} for ip, count in ip_counts.items() if count >= DDOS_THRESHOLD]
if ddos_list:
    st.dataframe(pd.DataFrame(ddos_list), use_container_width=True)
else:
    st.success("✅ Flow rates normal.")

st.markdown("### 🦠 Threat C: DGA Malware Alerts")
dga_list = []
for i in range(len(dga_predictions)):
    if dga_predictions[i] == -1 and X_data[i][2] > 3.0: # Only flag high entropy
        dga_list.append({
            "Source IP": ips[i],
            "Malicious Domain": websites[i],
            "Entropy Score": round(X_data[i][2], 2)
        })

if dga_list:
    st.dataframe(pd.DataFrame(dga_list).head(10), use_container_width=True)
else:
    st.success("✅ Network Secure.")

time.sleep(2)
st.rerun()
