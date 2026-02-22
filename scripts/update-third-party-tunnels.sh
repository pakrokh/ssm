#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${ROOT_DIR}/third_party/tunnels"

mkdir -p "${TARGET_DIR}"
cd "${TARGET_DIR}"

clone_or_update() {
  local name="$1"
  local url="$2"

  if [[ -d "${name}/.git" ]]; then
    echo "Updating ${name}..."
    git -C "${name}" fetch --depth 1 origin
    git -C "${name}" reset --hard FETCH_HEAD
  else
    echo "Cloning ${name}..."
    git clone --depth 1 "${url}" "${name}"
  fi
}

clone_or_update trusttunnel https://github.com/TrustTunnel/TrustTunnel.git
clone_or_update paqet https://github.com/hanselime/paqet.git
clone_or_update iodine https://github.com/yarrick/iodine.git
clone_or_update backhaul_script https://github.com/Azumi67/Backhaul_script.git
clone_or_update icmp_tun https://github.com/Azumi67/icmp_tun.git
clone_or_update reverse_tls https://github.com/Azumi67/Reverse_tls.git
clone_or_update udp_tun https://github.com/Azumi67/udp_tun.git
clone_or_update rathole https://github.com/rathole-org/rathole.git
clone_or_update frp https://github.com/fatedier/frp.git

echo
echo "Pinned revisions:"
for d in trusttunnel paqet iodine backhaul_script icmp_tun reverse_tls udp_tun rathole frp; do
  printf "  %-16s %s\n" "${d}" "$(git -C "${d}" rev-parse --short HEAD)"
done
