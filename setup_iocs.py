import sqlite3
import pyshark

conn = sqlite3.connect('iocs.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS c2_servers (ip TEXT, domain TEXT, hash TEXT)''')

try:
    cap = pyshark.FileCapture('rat_traffic.pcap')
    c2_ips = set()
    for pkt in cap:
        if 'IP' in pkt:
            c2_ips.add(pkt.ip.dst)
    iocs = [(ip, 'unknown.com', 'unknown') for ip in c2_ips]
except Exception as e:
    print(f"Error extracting IOCs: {e}")
    iocs = []

sample_iocs = [
    ('192.168.1.100', 'malicious.com', 'a1b2c3d4'),
    ('10.0.0.1', 'c2server.net', 'e5f6g7h8')
]
iocs.extend(sample_iocs)
cursor.executemany("INSERT INTO c2_servers (ip, domain, hash) VALUES (?, ?, ?)", iocs)
conn.commit()
conn.close()
print("IOCs loaded:", iocs)
