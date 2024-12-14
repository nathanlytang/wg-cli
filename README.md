# wg-cli
A tool to automate and manage WireGuard™ peers.

---

### Install
1. Clone the repository or download and unzip the .tar file into `/etc/wg-cli/`.
2. Compile `wg-cli.c` if cloning the repository.
3. Copy the binary into `/usr/local/bin/`.
4. Fill out `template.conf` in `/etc/wg-cli/`, leaving "PrivateKey" and "Address" blank.

### Usage

*   **`show [<interface>]`**: Displays information about WireGuard peers.
    *   If `interface` is provided, shows peers for the specified interface.
    *   If `interface` is omitted, shows all configured interfaces and their peers.

*   **`create-peer <interface> <peer-name> <allowed-ips>`**: Creates a new WireGuard peer.
    *   `interface`: The WireGuard interface name (e.g., `wg0`).
    *   `peer-name`:  A descriptive name for the peer (e.g., `phone`, `laptop`).
    *   `allowed-ips`: The IP address(es) or CIDR block(s) the peer is allowed to access (e.g., `192.168.2.10/32`, `10.0.0.0/24`).

*   **`remove-peer <interface> <peer-name>`**: Removes a WireGuard peer.
    *   `interface`: The WireGuard interface name.
    *   `peer-name`: The name of the peer to remove.
