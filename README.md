nano README.md
# 🛡️ NTRO Unidirectional Threat Monitor (Passive AI/ML Pipeline)

## Overview
This is a real-time, streaming Intrusion Detection System built for the SIH 2026 NTRO Problem Statement. It monitors unidirectional network traffic (like data diodes) and uses Machine Learning to detect zero-day cyber threats without requiring payload decryption or a two-way connection.

## Features
* **100% Passive Ingest:** Reads network logs without interacting with the source.
* **Live Streaming:** Processes data incrementally via a live dashboard.
* **AI-Powered (Threat C):** Uses an Isolation Forest machine learning model and Shannon Entropy calculations to detect DGA (Domain Generation Algorithm) malware beaconing.

## How to Run the Prototype
1. Create a virtual environment: `python3 -m venv venv`
2. Activate it: `source venv/bin/activate`
3. Install the tools: `pip install -r requirements.txt`
4. Launch the dashboard: `streamlit run dashboard.py`
