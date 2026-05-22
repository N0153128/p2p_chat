# p2p_chat

Serverless encrypted peer-to-peer chat over UDP. Works on local networks and across the internet via NAT hole-punching. Up to 32 people can share a single room.

## Features

- End-to-end encrypted (X25519 + XSalsa20-Poly1305 via PyNaCl)
- LAN auto-discovery — no IP addresses to copy; peers find each other automatically
- Internet mode — direct peer-to-peer via UDP hole-punching
- Up to 32 peers in a single room simultaneously
- Named rooms with optional passcode protection
- Host mode — one peer controls kicks, bans, slot count, and the message of the day (MOTD)
- Anonymous mode — hide your IP address everywhere in the UI (`-a` / `--anonymous`)
- Custom colours for your username and message text (saved between sessions)
- Peer colours transmitted at handshake — each peer's messages appear in their chosen colours
- Local echo of sent messages with a `(you)` prefix in your own colours
- Status bar showing all connected members and room capacity
- Tab key cycles through peers in the status bar (host: press `k` to kick, `B` to ban)
- Notification sound on incoming messages (via `paplay` / `aplay`)
- Colourful terminal greeting with ASCII-art title

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

### Anonymous mode

```
python3 client.py -a
python3 client.py --anonymous
```

Your public IP is replaced with `***.***.***.***` everywhere it would appear — in your own terminal and in any join/kick/ban notifications shown to other peers. Your port is still displayed so peers can connect.

### Local network (LAN)

Choose **l**. The app scans for active rooms on the network and lists them. Pick a numbered room to join, or enter **0** to create a new one.

```
Mode (l/g): l
  2 active rooms on this network:
  1  Friday hangout 🔒  [8 slots]
  2  dev chat           [4 slots]
  0  create a new room
```

Locked rooms (🔒) require a passcode. Discovery runs continuously in the background — new peers join automatically without interrupting the chat, and the room stays open after a peer disconnects.

#### Creating a room

When no rooms are found, or when you choose **0**, you are walked through a short setup:

- **Room name** — shown to everyone scanning the network
- **Slots** — how many people can join (2–32)
- **Host mode** — grants you kick, ban, passcode, and MOTD controls
- **Passcode** (host only) — digits only; leave blank for an open room
- **Message of the day** (host only) — shown to every peer on join

### Internet (global)

Choose **g**. Share your **public IP** and **chat port** (shown at startup) with your peers out-of-band (e.g. Signal, email). Enter one peer's details to initiate; additional peers can join mid-session by punching your public IP:port directly.

```
Mode (l/g): g
Peer's public IP: 1.2.3.4
Peer's port: 51234
```

## Commands

These can be typed at the input prompt during a chat session:

| Command | Who | Effect |
|---------|-----|--------|
| `/exit` | everyone | Leave the room. Sends a disconnect notice to all peers. |
| `/clear` | everyone | Clear the local chat scroll region (no effect on other peers). |
| `/mute` | everyone | Silence incoming notification sounds (for you only). |
| `/unmute` | everyone | Restore notification sounds. |
| `/motd <text>` | host only | Update the message of the day and broadcast it to all peers. |
| `/close` | host only | Close the room, force-disconnecting all peers immediately. |

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
| Banned peer rejoin | Host sends an unencrypted rejection packet immediately on reconnect attempt, before any handshake |
