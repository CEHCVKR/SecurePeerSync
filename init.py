import os
import socket
import uuid
import json
import threading
import base64
import time
from nacl.signing import SigningKey
from nacl.public import PrivateKey

BROADCAST_PORT = 65432
BROADCAST_INTERVAL = 5  # seconds

MY_IDENTITY_FILE = 'my_identity.json'
PEERS_FILE = 'peers.json'
MULTICAST_GROUP = '224.0.0.1'

def get_ip_mac():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()

    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff)
                    for i in range(0, 8*6, 8)][::-1])
    return local_ip, mac

def generate_keys():
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    private_key = PrivateKey.generate()
    public_key = private_key.public_key

    return {
        'signing_private': base64.b64encode(signing_key.encode()).decode(),
        'signing_public': base64.b64encode(verify_key.encode()).decode(),
        'x25519_private': base64.b64encode(private_key.encode()).decode(),
        'x25519_public': base64.b64encode(public_key.encode()).decode()
    }

def load_or_create_identity():
    if os.path.exists(MY_IDENTITY_FILE):
        with open(MY_IDENTITY_FILE, 'r') as f:
            identity = json.load(f)
    else:
        hostname = input("Enter a hostname for this device: ")
        ip, mac = get_ip_mac()
        keys = generate_keys()
        identity = {
            "hostname": hostname,
            "ip": ip,
            "mac": mac,
            **keys
        }
        with open(MY_IDENTITY_FILE, 'w') as f:
            json.dump(identity, f, indent=2)

    return identity

def load_peers():
    if os.path.exists(PEERS_FILE):
        with open(PEERS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_peers(peers):
    with open(PEERS_FILE, 'w') as f:
        json.dump(peers, f, indent=2)

def broadcast_identity(my_identity):
    ip_prefix = '.'.join(my_identity['ip'].split('.')[:3])
    broadcast_ip = f"{ip_prefix}.255"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    mcast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    mcast_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    payload = {
        "hostname": my_identity["hostname"],
        "ip": my_identity["ip"],
        "mac": my_identity["mac"],
        "signing_public": my_identity["signing_public"],
        "x25519_public": my_identity["x25519_public"]
    }

    message = json.dumps(payload).encode()

    while True:
        try:
            sock.sendto(message, (broadcast_ip, BROADCAST_PORT))
            mcast_sock.sendto(message, (MULTICAST_GROUP, BROADCAST_PORT))
            print(f"[BCAST] Sent identity: {payload['hostname']} ({payload['ip']})")
        except Exception as e:
            print(f"[ERROR] Broadcast failed: {e}")
        time.sleep(BROADCAST_INTERVAL)

def listen_for_broadcasts(my_identity):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', BROADCAST_PORT))

    # Multicast group join
    mcast = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    mcast.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mcast.bind(('', BROADCAST_PORT))
    mreq = socket.inet_aton(MULTICAST_GROUP) + socket.inet_aton(my_identity["ip"])
    mcast.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    peers = load_peers()

    def handle_socket(s):
        nonlocal peers
        while True:
            data, addr = s.recvfrom(2048)
            # print(f"[DEBUG] Raw data from {addr}: {data}")
            try:
                decoded = data.decode()
                # print(f"[DEBUG] Decoded JSON: {decoded}")
                peer = json.loads(decoded)

                # Avoid self
                if peer["ip"] == my_identity["ip"] and peer["mac"] == my_identity["mac"]:
                    continue

                if not any(p["ip"] == peer["ip"] for p in peers):
                    peers.append(peer)
                    save_peers(peers)
                    print(f"[RECV] New peer added: {peer['hostname']} ({peer['ip']})")

            except Exception as e:
                print(f"[ERROR] Failed to parse message: {e}")

    threading.Thread(target=handle_socket, args=(sock,), daemon=True).start()
    threading.Thread(target=handle_socket, args=(mcast,), daemon=True).start()

    # Keep main thread alive
    while True:
        time.sleep(1)

def main():
    try:
        my_identity = load_or_create_identity()
        threading.Thread(target=broadcast_identity, args=(my_identity,), daemon=True).start()
        listen_for_broadcasts(my_identity)
    except KeyboardInterrupt:
        print("\n[INFO] Terminated by user")
        exit(0)

if __name__ == '__main__':
    main()

