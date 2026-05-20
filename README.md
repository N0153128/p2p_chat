# p2p_chat

Serverless encrypted peer-to-peer chat over UDP. Works on local networks and across the internet via NAT hole-punching.

## Features

- End-to-end encrypted (X25519 + XSalsa20-Poly1305 via PyNaCl)
- LAN auto-discovery — no IP addresses to copy
- Internet mode — direct peer-to-peer via UDP hole-punching
- Custom colours for your username and message text
- Clean disconnect notification when a peer leaves

## Requirements

```
pip install -r requirements.txt
```

## Usage

```
python3 client.py
```

On startup you will be asked for your name and two colour choices (one for your username, one for your message text). Both peers must run the script before the connection can be established.

### Local network (LAN)

Both peers choose **l**, then enter the same room code. The room code authenticates the discovery beacon — only peers sharing the same code can find each other.

```
Mode (l/g): l
Room code (share this with your peer): mysecretroom
```

### Internet (global)

Both peers choose **g**. Share your **public IP** and **chat port** (shown at startup) with your peer out-of-band (e.g. Signal, email). Both peers enter each other's details. You have 30 seconds to connect before hole-punching times out.

```
Mode (l/g): g
Peer's public IP: 1.2.3.4
Peer's port: 51234
```

## Running tests

```
python3 -m pytest tests/
```

## Security

| Threat | Mitigation |
|--------|------------|
| Beacon hijacking | HMAC-SHA256 ties each beacon to the shared room code |
| Plaintext traffic | All chat is encrypted with a per-session nacl.public.Box |
| Control message injection | Packets from any address other than the connected peer are dropped |
