import requests
import pyshark
import pandas as pd
import joblib
import numpy as np

# Telegram Bot Config
TELEGRAM_TOKEN = '8027392228:AAFTapZQMZNsnZ7xiL9Vuz2FsCnQZX01Mf0'
TELEGRAM_CHAT_ID = '1157778897'
TELEGRAM_API = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage'

# Load the trained model
model = joblib.load('isolation_forest_ctu13.pkl')

# Updated PCAP file
pcap_file = '2019-01-04-Nanocore-RAT-infection-traffic.pcap'

# Extracted features (example-based, needs flow aggregation for accuracy)
features = []

try:
    cap = pyshark.FileCapture(pcap_file, only_summaries=True)
    for pkt in cap:
        try:
            pkt_len = float(pkt.length)
            protocol = pkt.protocol
            time = float(pkt.time)
            info = pkt.info

            # Dummy approximations for demo purposes (real flow-based metrics should be extracted using tools like Zeek)
            feature = {
                'TotLen Fwd Pkts': pkt_len if '->' in info else 0,
                'TotLen Bwd Pkts': pkt_len if '<-' in info else 0,
                'Fwd Pkt Len Std': np.random.uniform(0, 150),  # placeholder
                'Bwd Pkt Len Std': np.random.uniform(0, 150),  # placeholder
                'Pkt Len Mean': pkt_len,
                'Pkt Len Std': np.random.uniform(0, 50),  # placeholder
                'Fwd Pkts/s': np.random.uniform(0, 5),     # placeholder
                'Bwd Pkts/s': np.random.uniform(0, 5),     # placeholder
                'SYN Flag Cnt': 1 if 'SYN' in info else 0,
                'ACK Flag Cnt': 1 if 'ACK' in info else 0,
                'Flow Duration': np.random.uniform(0.1, 5),   # placeholder
                'Idle Mean': np.random.uniform(0, 10),        # placeholder
                'Idle Max': np.random.uniform(0, 20),         # placeholder
            }

            features.append(feature)
        except Exception as pkt_err:
            print(f"Error reading packet: {pkt_err}")

except Exception as e:
    print(f"Error processing PCAP: {e}")

# Anomaly Detection
live_data = pd.DataFrame(features)

# Only proceed if there's valid traffic data
if not live_data.empty:
    # Use only the trained feature columns
    selected_features = [
        'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
        'Fwd Pkt Len Std', 'Bwd Pkt Len Std',
        'Pkt Len Mean', 'Pkt Len Std',
        'Fwd Pkts/s', 'Bwd Pkts/s',
        'SYN Flag Cnt', 'ACK Flag Cnt',
        'Flow Duration', 'Idle Mean', 'Idle Max'
    ]

    # Handle missing or placeholder data
    X = live_data[selected_features].fillna(0)
    predictions = model.predict(X)

    # Notify for anomalies
    anomalies = live_data[predictions == -1]
    for _, row in anomalies.iterrows():
        alert = f"🚨 ALERT: RAT-like traffic detected! Pkt Len Mean: {row['Pkt Len Mean']:.2f}, Fwd Pkts/s: {row['Fwd Pkts/s']:.2f}"
        requests.post(TELEGRAM_API, data={'chat_id': TELEGRAM_CHAT_ID, 'text': alert})
        print(alert)
else:
    print("No valid traffic to analyze.")

