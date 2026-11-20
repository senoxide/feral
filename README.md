# feral

peer-to-peer lan chat with no server, no accounts, and no signup. peers find
each other over udp and talk over encrypted tcp.

## build

```
git clone https://github.com/sixteenjune/feral
cd feral
cargo build --release --target x86_64-unknown-linux-gnu
```

the default target is windows (gnu/mingw) so install the `x86_64-pc-windows-gnu` target and minGW, then just `cargo build --release`.

supported: linux, windows. macos: not supported.

## usage

run `feral`, then `/help` for the full command list. the basics:

- `/who` — list peers on the network
- `/name <name>` — set your display name
- `/msg <name|id> <text>` — private message
- `/sendfile <name|id> <path>` — send a file
- `/fingerprint [name|id]` — show an identity fingerprint

fingerprints are sha-256 hashes of each peer's permanent identity key. you don't need to check them day to day, but if you want to be sure who you're talking to, compare fingerprints over a call or in person.
