from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
import base64

app = Flask(__name__)
socketio = SocketIO(app)

private_key = RSA.generate(2048)
public_key = private_key.publickey()

session_keys = {}
@app.route('/')
def index():
    return render_template('index.html', public_key=public_key.export_key().decode())

@socketio.on('connect')
def handle_connect():
    emit('public_key', {'public_key': public_key.export_key().decode()})

@socketio.on('aes_key')
def handle_aes_key(data):
    try:
        print(f"Received AES key for session {data['sid']}: {data['aes_key']}")
        encrypted_key = base64.b64decode(data['aes_key'])
        print(f"Base64-decoded AES key: {encrypted_key}")
        
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_key)
        session_keys[data['sid']] = aes_key
        print(f"AES key received and decrypted for session: {data['sid']}")
    except (ValueError, KeyError) as e:
        print(f"Error decrypting AES key for session {data['sid']}: {e}")
        emit('error', {'message': f"Error decrypting AES key for session {data['sid']}: {e}"})

@socketio.on('message')
def handle_message(data):
    sid = data['sid']
    aes_key = session_keys.get(sid)
    if aes_key is None:
        print(f"AES key not found for session: {sid}")
        return

    try:
        encrypted_message = base64.b64decode(data['message'])
        nonce = base64.b64decode(data['nonce'])

        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_message = cipher_aes.decrypt(encrypted_message).decode()

        print(f"Decrypted message: {decrypted_message}")
        emit('message', {'message': data['message'], 'nonce': data['nonce'], 'decrypted_message': decrypted_message}, broadcast=True)
    except Exception as e:
        print(f"Error decrypting message for session {sid}: {e}")
        emit('error', {'message': f"Error decrypting message for session {sid}: {e}"})

if __name__ == '__main__':
    socketio.run(app, debug=True)
