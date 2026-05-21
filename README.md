# p2p_chat

Serverless encrypted peer-to-peer chat over UDP. Works on local networks and across the internet via NAT hole-punching. Up to 16 people can share a single room.

## Features

- End-to-end encrypted (X25519 + XSalsa20-Poly1305 via PyNaCl)
- LAN auto-discovery — no IP addresses to copy; peers join live as they enter the room code
- Internet mode — direct peer-to-peer via UDP hole-punching
- Up to 16 peers in a single room simultaneously
- Custom colours for your username and message text (saved between sessions)
- Local echo of sent messages with a `(you)` prefix in your own colours
- Peer colours transmitted at handshake — each peer's messages appear in their chosen colours
- Notification sound on incoming messages (via `paplay` / `aplay`)
- Colourful terminal greeting with ASCII-art title in green→red gradient
- Colour picker menus erase themselves after selection

## Requirements

```
pip install -r requirements.txt
```

Notification sounds require PulseAudio (`paplay`) or ALSA (`aplay`), both standard on Linux.

## Usage

```
python3 client.py
```

On startup a greeting screen is displayed, then you are prompted for your name and two colour choices (one for your username, one for your message text). Preferences are saved to `~/.p2p_chat.json` and pre-filled on the next run.

### Local network (LAN)

Choose **l** and enter a room code. Discovery runs continuously in the background for the life of the room — new peers join automatically as they enter the same code, without interrupting the chat.

```
Mode (l/g): l
Room code (share this with your peer): mysecretroom
```

The room stays open after a peer disconnects. Remaining peers keep chatting; the disconnected peer can rejoin at any time with the same code.

### Internet (global)

Choose **g**. Share your **public IP** and **chat port** (shown at startup) with your peers out-of-band (e.g. Signal, email). Enter one peer's details to initiate; additional peers can join mid-session by punching your public IP:port directly.

```
Mode (l/g): g
Peer's public IP: 1.2.3.4
Peer's port: 51234
```

## Commands

These can be typed at the `> ` prompt during a chat session:

| Command | Effect |
|---------|--------|
| `/exit` | Leave the room and return to mode selection. Sends a disconnect notice to all peers. |
| `/mute` | Silence incoming notification sounds from all peers (for you only). |
| `/unmute` | Restore notification sounds from all peers. |

## Running tests

```
python3 -m pytest tests/
```

## Security

| Threat | Mitigation |
|--------|------------|
| Beacon hijacking | HMAC-SHA256 ties each beacon to the shared room code |
| Plaintext traffic | All chat is encrypted with a per-session `nacl.public.Box` per peer |
| Control message injection | Only authenticated peers' packets are processed; unknown sources are dropped except for initial PUNCH handshakes |
