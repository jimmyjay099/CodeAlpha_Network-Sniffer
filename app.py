# backend/app.py
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import threading
import time
import sys
import os
import ctypes

# Import Scapy (ensure it's installed: pip install scapy)
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    from scapy.layers.inet import IP, TCP, UDP, ICMP # Explicitly import for clarity
except ImportError:
    print("Scapy not found. Please install it using 'pip install scapy'.")
    sys.exit(1)

app = Flask(__name__)
# Allow CORS for your React frontend (adjust origin in production)
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variable to control sniffing
sniffing_active = False
sniff_thread = None

# Function to process each captured packet and emit to frontend
def packet_callback(packet):
    """
    Processes a captured packet, extracts relevant information,
    and emits it to connected WebSocket clients.
    """
    if not sniffing_active:
        return # Stop processing if sniffing is no longer active

    packet_data = {
        "id": str(time.time()) + str(packet.time), # Unique ID for React key
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time)),
        "srcIp": "N/A",
        "dstIp": "N/A",
        "protocol": "N/A",
        "srcPort": "-",
        "dstPort": "-",
        "payloadSummary": "",
        "fullPayload": "",
        "layers": {}
    }

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        packet_data["srcIp"] = ip_layer.src
        packet_data["dstIp"] = ip_layer.dst
        packet_data["protocol"] = str(ip_layer.proto) # Default to number
        packet_data["layers"]["ip"] = {
            "version": ip_layer.version,
            "headerLen": ip_layer.ihl * 4, # IP Header Length in bytes
            "ttl": ip_layer.ttl,
            "id": ip_layer.id,
            "flags": str(ip_layer.flags),
            "checksum": hex(ip_layer.chksum)
        }

        # Determine protocol name
        if ip_layer.proto == 6:
            packet_data["protocol"] = "TCP"
        elif ip_layer.proto == 17:
            packet_data["protocol"] = "UDP"
        elif ip_layer.proto == 1:
            packet_data["protocol"] = "ICMP"

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            packet_data["srcPort"] = str(tcp_layer.sport)
            packet_data["dstPort"] = str(tcp_layer.dport)
            packet_data["layers"]["tcp"] = {
                "sport": tcp_layer.sport,
                "dport": tcp_layer.dport,
                "seq": tcp_layer.seq,
                "ack": tcp_layer.ack,
                "dataofs": tcp_layer.dataofs * 4, # Data Offset in bytes
                "flags": str(tcp_layer.flags),
                "window": tcp_layer.window,
                "checksum": hex(tcp_layer.chksum),
                "urgptr": tcp_layer.urgptr
            }
            if tcp_layer.payload:
                try:
                    raw_payload = bytes(tcp_layer.payload)
                    packet_data["fullPayload"] = raw_payload.hex() # Hex representation
                    packet_data["payloadSummary"] = raw_payload.decode('utf-8', errors='ignore')[:50] + "..." if len(raw_payload) > 50 else raw_payload.decode('utf-8', errors='ignore')
                except Exception:
                    packet_data["payloadSummary"] = f"TCP Payload ({len(raw_payload)} bytes)"

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            packet_data["srcPort"] = str(udp_layer.sport)
            packet_data["dstPort"] = str(udp_layer.dport)
            packet_data["layers"]["udp"] = {
                "sport": udp_layer.sport,
                "dport": udp_layer.dport,
                "length": udp_layer.len,
                "checksum": hex(udp_layer.chksum)
            }
            if udp_layer.payload:
                try:
                    raw_payload = bytes(udp_layer.payload)
                    packet_data["fullPayload"] = raw_payload.hex()
                    packet_data["payloadSummary"] = raw_payload.decode('utf-8', errors='ignore')[:50] + "..." if len(raw_payload) > 50 else raw_payload.decode('utf-8', errors='ignore')
                except Exception:
                    packet_data["payloadSummary"] = f"UDP Payload ({len(raw_payload)} bytes)"

        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            packet_data["layers"]["icmp"] = {
                "type": icmp_layer.type,
                "code": icmp_layer.code,
                "checksum": hex(icmp_layer.chksum)
            }
            packet_data["payloadSummary"] = f"ICMP Type: {icmp_layer.type}, Code: {icmp_layer.code}"
            if icmp_layer.payload:
                try:
                    raw_payload = bytes(icmp_layer.payload)
                    packet_data["fullPayload"] = raw_payload.hex()
                    packet_data["payloadSummary"] += f" ({len(raw_payload)} bytes)"
                except Exception:
                    pass # Ignore payload if it's not easily decodable

        # If no specific transport layer, try to get raw payload from IP layer
        elif ip_layer.payload:
            try:
                raw_payload = bytes(ip_layer.payload)
                packet_data["fullPayload"] = raw_payload.hex()
                packet_data["payloadSummary"] = raw_payload.decode('utf-8', errors='ignore')[:50] + "..." if len(raw_payload) > 50 else raw_payload.decode('utf-8', errors='ignore')
            except Exception:
                packet_data["payloadSummary"] = f"IP Payload ({len(raw_payload)} bytes)"

    else:
        # For non-IP packets (e.g., ARP, Ethernet)
        packet_data["protocol"] = "Ethernet"
        packet_data["payloadSummary"] = f"Non-IP packet ({len(packet)} bytes)"
        packet_data["fullPayload"] = bytes(packet).hex()
        if packet.haslayer("Ethernet"):
            eth_layer = packet.getlayer("Ethernet")
            packet_data["layers"]["ethernet"] = {
                "src": eth_layer.src,
                "dst": eth_layer.dst,
                "type": hex(eth_layer.type)
            }


    # Emit the packet data to all connected clients
    socketio.emit('new_packet', packet_data)

# Function to run sniffing in a separate thread
def run_sniffer():
    global sniffing_active
    print("Sniffer thread started.")
    try:
        # You might need to specify an interface here, e.g., iface="eth0" or iface="Wi-Fi"
        # On Windows, use `show_interfaces()` in a separate script to find names/GUIDs.
        # Example: sniff(prn=packet_callback, store=0, iface="Wi-Fi")
        sniff(prn=packet_callback, store=0, stop_filter=lambda x: not sniffing_active)
    except Exception as e:
        print(f"Error in sniffer thread: {e}")
        # Emit an error message to the frontend if sniffing fails
        socketio.emit('sniffer_error', {'message': str(e), 'details': 'Ensure proper permissions (run as administrator/root) and check your network interface.'})
    finally:
        print("Sniffer thread stopped.")
        sniffing_active = False # Ensure status is updated if thread exits unexpectedly

# API endpoint to start sniffing
@app.route('/start_sniffing', methods=['POST'])
def start_sniffing():
    global sniffing_active, sniff_thread
    if not sniffing_active:
        sniffing_active = True
        # Start sniffing in a separate thread to not block the Flask app
        sniff_thread = threading.Thread(target=run_sniffer)
        sniff_thread.daemon = True # Allow main program to exit even if thread is running
        sniff_thread.start()
        return jsonify({"status": "Sniffing started", "message": "Packet capture initiated."})
    return jsonify({"status": "Already sniffing", "message": "Sniffing is already active."}), 409

# API endpoint to stop sniffing
@app.route('/stop_sniffing', methods=['POST'])
def stop_sniffing():
    global sniffing_active, sniff_thread
    if sniffing_active:
        sniffing_active = False
        # Give a small delay for the sniff thread to acknowledge stop_filter
        if sniff_thread and sniff_thread.is_alive():
            sniff_thread.join(timeout=2) # Wait for thread to finish
        sniff_thread = None
        return jsonify({"status": "Sniffing stopped", "message": "Packet capture terminated."})
    return jsonify({"status": "Not sniffing", "message": "Sniffing is not active."}), 409

# Root endpoint (optional, for testing if backend is up)
@app.route('/')
def index():
    return "Network Sniffer Backend is running!"

@socketio.on('connect')
def test_connect():
    print('Client connected')
    emit('status', {'message': 'Connected to backend WebSocket'})

@socketio.on('disconnect')
def test_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    # Check for root/administrator privileges (important for sniffing)
    if os.name == 'posix' and os.geteuid() != 0:
        print("Warning: Running as non-root user. Packet capturing might not work without sufficient permissions.")
        print("Please try running with 'sudo python app.py'")
    elif os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        print("Warning: Running as non-administrator. Packet capturing might not work without sufficient permissions.")
        print("Please try running as Administrator.")

    # Run the Flask app with SocketIO
    # Use host='0.0.0.0' to make it accessible from other devices on your network
    # Use debug=True for development (auto-reloads, but not for production)
    socketio.run(app, host='127.0.0.1', port=5000, debug=False, allow_unsafe_werkzeug=True)
