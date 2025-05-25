from nacl.signing import VerifyKey
from nacl.public import PrivateKey, PublicKey, Box
import base64, socket, json

def load_identity():
    with open("my_identity.json") as f:
        return json.load(f)

def get_peer_by_ip(ip):
    with open("peers.json") as f:
        peers = json.load(f)
    return next((p for p in peers if p["ip"] == ip), None)

def receive():
    my_identity = load_identity()
    my_priv = PrivateKey(base64.b64decode(my_identity["x25519_private"]))

    sock = socket.socket()
    sock.bind(("", 9000))
    sock.listen(1)
    print("[*] Waiting for file...")

    conn, addr = sock.accept()
    data = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    conn.close()

    peer = get_peer_by_ip(addr[0])
    if not peer:
        print("[!] Unknown sender.")
        return

    try:
        payload = json.loads(data.decode())
        file_name = payload["file_name"]
        signed_data = base64.b64decode(payload["signed_data"])

        verify_key = VerifyKey(base64.b64decode(peer["signing_public"]))
        verified_data = verify_key.verify(signed_data)

        box = Box(my_priv, PublicKey(base64.b64decode(peer["x25519_public"])))
        decrypted = box.decrypt(verified_data)

        # Save using original file name
        with open(file_name, "wb") as f:
            f.write(decrypted)
        print(f"[+] File '{file_name}' received and verified!")

    except Exception as e:
        print("[!] Verification or decryption failed:", e)

# Start receiving
receive()
