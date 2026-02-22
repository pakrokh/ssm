# Third-Party Tunnel Sources (Self-Hosted)

This directory vendors the upstream source repositories used by the Smite tunnel provider catalog.

## Included Repositories

1. `trusttunnel` -> https://github.com/TrustTunnel/TrustTunnel
2. `paqet` -> https://github.com/hanselime/paqet
3. `iodine` -> https://github.com/yarrick/iodine
4. `backhaul_script` -> https://github.com/Azumi67/Backhaul_script
5. `icmp_tun` -> https://github.com/Azumi67/icmp_tun
6. `reverse_tls` -> https://github.com/Azumi67/Reverse_tls
7. `udp_tun` -> https://github.com/Azumi67/udp_tun
8. `rathole` -> https://github.com/rathole-org/rathole
9. `frp` -> https://github.com/fatedier/frp

## Why This Exists

- Keep all requested tunnel projects self-hosted in one project tree.
- Allow offline packaging (zip/tar) and manual upload to your own repository.
- Preserve Smite provider mapping while keeping upstream source code local.

## Refresh Upstream Sources

Run this from project root:

```bash
bash scripts/update-third-party-tunnels.sh
```

## Notes

- These are upstream projects with their own licenses and release cycles.
- Keep original license files when mirroring/updating.
