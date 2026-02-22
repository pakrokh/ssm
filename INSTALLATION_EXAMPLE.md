# Smite Installation Example

This file gives copy/paste examples for panel and node installation.

## Panel Installation

### Quick Install

```bash
sudo bash -c "$(curl -sL https://raw.githubusercontent.com/zZedix/Smite/main/scripts/install.sh)"
```

### Manual Install

```bash
git clone https://github.com/zZedix/Smite.git
cd Smite
cp .env.example .env
sudo bash cli/install_cli.sh
docker compose up -d
smite admin create
```

Panel UI example:

```text
http://SERVER_IP:8000
```

## Node Installation

### Architecture

- Iran Nodes: run tunnel clients and forwarders. Use `NODE_ROLE=iran` and panel `ca.crt`.
- Foreign Nodes: run tunnel server-side parts. Use `NODE_ROLE=foreign` and panel `ca-server.crt`.

### Quick Install

```bash
sudo bash -c "$(curl -sL https://raw.githubusercontent.com/zZedix/Smite/main/scripts/smite-node.sh)"
```

### Manual Install Example (Iran Node)

```bash
git clone https://github.com/zZedix/Smite.git
cd Smite/node
mkdir -p certs config
# Copy panel Iran CA certificate:
#   /path/to/panel/certs/ca.crt -> ./certs/ca.crt

cat > .env << 'EOF'
NODE_API_PORT=8888
NODE_NAME=iran-node-1
NODE_ROLE=iran
SMITE_VERSION=latest
PANEL_CA_PATH=/etc/smite-node/certs/ca.crt
PANEL_ADDRESS=panel.example.com:443
PANEL_API_PORT=8000
EOF

docker compose up -d
```

### Manual Install Example (Foreign Node)

```bash
git clone https://github.com/zZedix/Smite.git
cd Smite/node
mkdir -p certs config
# Copy panel Foreign CA certificate:
#   /path/to/panel/certs/ca-server.crt -> ./certs/ca.crt

cat > .env << 'EOF'
NODE_API_PORT=8888
NODE_NAME=foreign-node-1
NODE_ROLE=foreign
SMITE_VERSION=latest
PANEL_CA_PATH=/etc/smite-node/certs/ca.crt
PANEL_ADDRESS=panel.example.com:443
PANEL_API_PORT=8000
EOF

docker compose up -d
```

## Notes

- If panel is not behind HTTPS reverse proxy, use panel node port directly in `PANEL_ADDRESS` (default from `.env.example` is `4443`).
- Check node logs with:

```bash
docker compose logs -f smite-node
```

- To refresh all vendored third-party tunnel sources in this project:

```bash
bash scripts/update-third-party-tunnels.sh
```
