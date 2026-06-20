from flask import Flask, render_template
from flask_socketio import SocketIO
import socket
import struct
import threading

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# UDP Collector Setup
UDP_IP = "0.0.0.0"
UDP_PORT = 54321


def collector_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    print(f"Collector listening on {UDP_PORT}...")

    while True:
        data, addr = sock.recvfrom(2048)
        # Simplified parsing of the INT metadata we added in P4
        # Adjust offsets based on your specific header stack
        try:
            # Taking first 32 bits as Switch ID, next 32 as Latency
            sw_id = struct.unpack("!I", data[42:46])[0]
            latency = struct.unpack("!I", data[50:54])[0]

            # Send to Web UI
            socketio.emit('telemetry_update', {
                'switch_id': sw_id,
                'latency': latency,
                'timestamp': threading.get_native_id()
            })
        except:
            pass


@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    threading.Thread(target=collector_thread, daemon=True).start()
    socketio.run(app, host='0.0.0.0', port=5000)