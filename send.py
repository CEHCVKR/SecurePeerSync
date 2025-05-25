from nacl.public import Box, PublicKey, PrivateKey
from nacl.signing import SigningKey
import json, base64, socket, os

def load_identity():
    with open("my_identity.json") as f:
        return json.load(f)

def get_peer_by_ip(ip):
    with open("peers.json") as f:
        peers = json.load(f)
    return next((p for p in peers if p["ip"] == ip), None)

def encrypt_and_send(file_path, peer_ip):
    my_identity = load_identity()
    peer = get_peer_by_ip(peer_ip)
    if not peer:
        print("Peer not found.")
        return

    # Load keys
    my_priv = PrivateKey(base64.b64decode(my_identity["x25519_private"]))
    peer_pub = PublicKey(base64.b64decode(peer["x25519_public"]))
    box = Box(my_priv, peer_pub)

    # Read file
    with open(file_path, "rb") as f:
        file_data = f.read()
    encrypted_data = box.encrypt(file_data)

    # Sign
    signing_key = SigningKey(base64.b64decode(my_identity["signing_private"]))
    signed_data = signing_key.sign(encrypted_data)

    # Send filename with extension as metadata
    file_name = os.path.basename(file_path)

    payload = {
        "file_name": file_name,
        "signed_data": base64.b64encode(signed_data).decode()
    }

    # Send over socket
    sock = socket.socket()
    sock.connect((peer_ip, 9000))
    sock.sendall(json.dumps(payload).encode())
    sock.close()

    print(f"[+] Sent '{file_name}' securely to {peer_ip}")

# Example usage
encrypt_and_send("FR011.py", "192.168.31.214")
