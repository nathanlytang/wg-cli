# wg-cli
A tool to automate and handle WireGuard™ peer management.

---

### Install
1. Clone the repository into `/etc/`.
2. Compile `wg-cli.c` and copy the binary into `/usr/local/bin`.
3. Fill out `template.conf`, leaving "PrivateKey" and "Address" blank.

### Usage
- create-peer:  Generates a new peer configuration file and copies the peer into the Wireguard™ interface configuration file.
- remove-peer: 🚧 In progress 🚧
