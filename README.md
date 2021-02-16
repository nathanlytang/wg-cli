# wg-cli
A tool to automate and manage WireGuard™ peers.

---

### Install
1. Clone the repository or download and unzip the .tar file into `/etc/wg-cli/`.
2. Compile `wg-cli.c` if cloning the repository.
3. Copy the binary into `/usr/local/bin/`.
4. Fill out `template.conf` in `/etc/wg-cli/`, leaving "PrivateKey" and "Address" blank.

### Usage
- create-peer: Generates a new peer configuration file and copies the peer into the Wireguard™ interface configuration file.
- remove-peer: Removes an existing peer from the interface configuration file and deletes the peer configuration file.
- show: 🚧 In progress 🚧
