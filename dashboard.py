import streamlit as st
import pandas as pd
import math
import time
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

# --- LOAD & PROCESS DATA ---
websites = []
ips = []

with open("clean_dns.txt", "r") as file:
    for line in file:
        cols = line.split()
        if len(cols) == 2:
            ips.append(cols[0])
            websites.append(cols[1])

X_data = [extract_features(site) for site in websites]

# Train AI
model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
if len(X_data) > 0:
    model.fit(X_data)
    predictions = model.predict(X_data)
else:
    predictions = []

# --- SCOREBOARD UI ---
total_traffic = len(predictions)
threats_detected = list(predictions).count(-1)

col1, col2, col3 = st.columns(3)
col1.metric("🌐 Total Flows Analyzed", total_traffic)
col2.metric("🚨 Threats Detected", threats_detected)
col3.metric("🔒 System Status", "ACTIVE - PASSIVE MODE")

st.markdown("### 🔴 Active Threat Alerts (Threat C: DGA Domains)")

threat_list = []
for i in range(len(predictions)):
    if predictions[i] == -1:
        feats = X_data[i]
        threat_list.append({
            "Source IP": ips[i],
            "Malicious Domain": websites[i],
            "Entropy Score": round(feats[2], 2),
            "Vowel Ratio": round(feats[1], 2),
            "Confidence": "HIGH"
        })

if len(threat_list) > 0:
    df = pd.DataFrame(threat_list)
    st.dataframe(df, use_container_width=True)
    st.error("⚠️ CRITICAL: DGA Beaconing detected. Do not establish return paths to the Source IPs.")
else:
    st.success("✅ Network Secure. No anomalies detected.")

# --- THE LIVE STREAMING MAGIC ---
# This tells the dashboard to wait 2 seconds, then completely rerun the script to check for new data!
time.sleep(2)
st.rerun()
