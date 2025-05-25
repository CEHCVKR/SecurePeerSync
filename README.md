
# SecurePeerSync

> SecurePeerSync: Encrypted Peer-to-Peer File Sharing with Automatic Peer Discovery  
> **Author**: CHINNAPAREDDY VENKATA KARTHIK REDDY  
> **For Educational and Ethical Research Purposes Only**

SecurePeerSync is a Python-based peer-to-peer file transfer application that enables secure, encrypted file sharing within a local network. It automatically discovers peers using broadcast and multicast, and ensures confidentiality and authenticity by combining public-key encryption (NaCl libsodium) with digital signatures.

---

## Features

- **Peer Discovery:** Automatically discovers peers on the same local network using UDP broadcast and multicast.
- **End-to-End Encryption:** Uses X25519 public/private keys for encrypting files between sender and receiver.
- **Digital Signatures:** Files are signed to guarantee authenticity and integrity.
- **Simple File Transfer:** Send and receive files securely by specifying the peer IP address.
- **Easy Setup:** Generates cryptographic identity keys on first run and manages peers dynamically.

---

## Getting Started

### Prerequisites

- Python 3.7+
- Dependencies listed in `requirements.txt`:
  - `pynacl`

Install dependencies using pip:

```bash
pip install pynacl
```

### Installation

1. Clone the repository:

```bash
git clone https://github.com/CEHCVKR/SecurePeerSync.git
cd SecurePeerSync
```

2. Run the main script to start broadcasting your identity and listen for peers:

```bash
python init.py
```

3. On first run, you will be prompted to enter a hostname for your device, and cryptographic keys will be generated automatically.

### Sending Files

Use the `sender.py` script to send files to a peer on the network:

```bash
python sender.py <file_path> <peer_ip>
```

Example:

```bash
python sender.py FR011.py 192.168.31.214
```

### Receiving Files

Run the `receiver.py` script to listen and receive incoming files:

```bash
python receiver.py
```

---

## Project Structure

```
SecurePeerSync/
│
├── init.py           # Main script: identity broadcast & peer discovery
├── sender.py         # Script to encrypt and send files to peers
├── receiver.py       # Script to receive, verify and decrypt files
├── my_identity.json  # Generated cryptographic identity (private + public keys)
├── peers.json        # Discovered peer info (hostnames, IPs, public keys)
├── requirements.txt  # Python dependencies
└── README.md         # Project documentation
```

---

## Security Notes

- All communication is encrypted using NaCl's public-key cryptography (libsodium).
- Files are signed before sending to ensure authenticity.
- Only peers discovered and stored in `peers.json` can be communicated with.
- Keys are generated and stored locally; keep `my_identity.json` secure.

---

## Future Enhancements

- GUI interface for easier file selection and transfer.
- Support for sending files to multiple peers simultaneously.
- Enhanced peer trust management and blacklist/whitelist.
- Support for larger file chunking and resume capabilities.

---


## 📬 Contact

- 📧 Email: [22bq1a4720@gmail.com](mailto:22bq1a4720@gmail.com)
- 🌐 GitHub: [@CEHCVKR](https://github.com/CEHCVKR)
- 💼 LinkedIn: [@cvkr](https://linkedin.com/in/cvkr)

---

**SecurePeerSync** — Secure your local network file sharing effortlessly.
