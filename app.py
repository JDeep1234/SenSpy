from flask import Flask, render_template, jsonify
import threading
import time
import socket
from scapy.all import *
from sklearn.ensemble import IsolationForest
import numpy as np

app = Flask(__name__)

# Get the system's IP address
host_name = socket.gethostname()
system_ip = socket.gethostbyname(host_name)

# Global variables for real-time plotting and packet information
time_points = []
incoming_traffic = []
outgoing_traffic = []
packet_info = []

# Initialize the Isolation Forest model
model = IsolationForest(contamination=0.1)

def detect_anomaly(data):
    if len(data) < 2:
        return np.ones(len(data))  # No anomalies detected if data is insufficient
    predictions = model.fit_predict(data)
    return predictions

def analyze_packet(packet):
    global system_ip
    packet_time = time.time()

    # Count incoming and outgoing packets
    incoming_count = sum(1 for pkt in packet if pkt.haslayer(IP) and pkt[IP].dst == system_ip)
    outgoing_count = sum(1 for pkt in packet if pkt.haslayer(IP) and pkt[IP].src == system_ip)

    incoming_traffic.append(incoming_count)
    outgoing_traffic.append(outgoing_count)

    # Update global lists for real-time plotting
    time_points.append(packet_time)

    # Use the last N values for anomaly detection
    window_size = 10
    if len(incoming_traffic) < window_size:
        data_window = np.array(list(zip(incoming_traffic, outgoing_traffic)))
    else:
        data_window = np.array(list(zip(incoming_traffic[-window_size:], outgoing_traffic[-window_size:])))

    # Update packet information list
    threat_detected = detect_anomaly(data_window)[-1] == -1
    threat_location = "Unknown"  # Replace with your logic to determine threat location

    packet_info.append({
        "Time": packet_time,
        "Source IP": packet[IP].src if packet.haslayer(IP) else "",
        "Destination IP": packet[IP].dst if packet.haslayer(IP) else "",
        "Threat Detected": "Yes" if threat_detected else "No",
        "Threat Location": threat_location
    })

def sniff_packets():
    sniff(prn=lambda pkt: analyze_packet(pkt), store=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/data')
def get_data():
    global time_points, incoming_traffic, outgoing_traffic, packet_info
    return jsonify({
        'time_points': time_points,
        'incoming_traffic': incoming_traffic,
        'outgoing_traffic': outgoing_traffic,
        'packet_info': packet_info,
    })

if __name__ == '__main__':
    # Start packet sniffing in a separate thread
    sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
    sniff_thread.start()

    # Run the Flask app on localhost:5000
    app.run(debug=True, port=5000, host='127.0.0.1')
