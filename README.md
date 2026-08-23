An anonymous peer-to-peer chat for your LAN. No server, accounts, or
address book. Peers find each other over UDP and chat over encrypted
TCP connections.

git clone https://github.com/sixteenjune/feral
cd feral
cargo build --release

Run `feral` and use `/help` for the full command list. Basic commands:

* `/who` — list peers
* `/name <name>` — set your display name
* `/msg <name|id> <text>` — send a private message
* `/sendfile <name|id> <path>` — upload and send a file link
* `/fingerprint [name|id]` — show an identity fingerprint

Fingerprints are SHA-256 hashes of the permanent identity key. You
normally do not need to check them. For trusted first contact, compare
the fingerprint with the person over a voice call or in person; names
and short IDs are not proof of identity.

The default build target is Windows GNU/MinGW. Install the
`x86_64-pc-windows-gnu` Rust target and MinGW, then run:

    cargo build --release

For Linux:

    cargo build --release --target x86_64-unknown-linux-gnu

Supported platforms are Linux and Windows. macOS is not supported.

Contributions welcome — open a PR with changes.
