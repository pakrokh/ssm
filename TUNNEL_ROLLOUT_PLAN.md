# Tunnel Rollout Plan (Smite Integration)

This runbook tracks onboarding of the 9 requested tunnel projects into Smite in the exact requested order.

## Rollout Order
1. `trusttunnel`
2. `paqet`
3. `iodine`
4. `backhaul_script`
5. `icmp_tun`
6. `reverse_tls`
7. `udp_tun`
8. `rathole`
9. `frp`

## Provider Matrix
| order | provider_id | mapped_core | runtime_mode | default_type | supported_types | default_ports | repo |
|---|---|---|---|---|---|---|---|
| 1 | `trusttunnel` | `gost` | `docker_build` | `tcp` | `tcp,udp` | `443` | https://github.com/TrustTunnel/TrustTunnel?tab=readme-ov-file#install-the-endpoint |
| 2 | `paqet` | `gost` | `docker_build` | `tcp` | `tcp,udp` | `9999` | https://github.com/hanselime/paqet |
| 3 | `iodine` | `gost` | `docker_build` | `udp` | `udp,tcp` | `53` | https://github.com/yarrick/iodine |
| 4 | `backhaul_script` | `backhaul` | `external_script` | `tcpmux` | `tcp,udp,ws,wsmux,tcpmux` | `443` | https://github.com/Azumi67/Backhaul_script |
| 5 | `icmp_tun` | `gost` | `external_script` | `udp` | `udp,tcp` | `8004` | https://github.com/Azumi67/icmp_tun |
| 6 | `reverse_tls` | `gost` | `external_script` | `tcp` | `tcp,udp,ws` | `443` | https://github.com/Azumi67/Reverse_tls |
| 7 | `udp_tun` | `gost` | `external_script` | `udp` | `udp,tcp` | `8004` | https://github.com/Azumi67/udp_tun |
| 8 | `rathole` | `rathole` | `docker_image` | `tcp` | `tcp,ws` | `443` | https://github.com/rathole-org/rathole |
| 9 | `frp` | `frp` | `docker_image` | `tcp` | `tcp,udp` | `443` | https://github.com/fatedier/frp |

## Smite Implementation Status
| provider_id | status | notes |
|---|---|---|
| `trusttunnel` | `done` | Added to provider catalog and UI create flow; mapped to `gost`. |
| `paqet` | `done` | Added to provider catalog and UI create flow; mapped to `gost`. |
| `iodine` | `done` | Added to provider catalog and UI create flow; mapped to `gost`. |
| `backhaul_script` | `phase_a_done` | Added as script-first profile with `runtime_mode=external_script`; mapped to `backhaul`. |
| `icmp_tun` | `phase_a_done` | Added as script-first profile with `runtime_mode=external_script`; mapped to `gost`. |
| `reverse_tls` | `phase_a_done` | Added as script-first profile with `runtime_mode=external_script`; mapped to `gost`. |
| `udp_tun` | `phase_a_done` | Added as script-first profile with `runtime_mode=external_script`; mapped to `gost`. |
| `rathole` | `done` | Added as docker-image profile and existing Smite runtime path remains active. |
| `frp` | `done` | Added as docker-image profile and existing Smite runtime path remains active. |

## API Contract Used
- `GET /api/tunnels/providers`
- `POST /api/tunnels`
- `PUT /api/tunnels/{tunnel_id}`
- `POST /api/tunnels/{tunnel_id}/apply`
- `POST /api/tunnels/reapply-all`

## Validation Completed
- Frontend build: `npm run build` in `frontend/`.
- Backend syntax validation:
  - `python3 -m compileall panel/app`
  - `python3 -m compileall node/app`

## Remaining Runtime Validation
- Live deploy/reapply and tunnel log validation require running panel + iran/foreign nodes with real connectivity.
- Script-first providers (`backhaul_script`, `icmp_tun`, `reverse_tls`, `udp_tun`) are integrated as Phase A metadata profiles and still require provider-specific containerization workflow for full Phase B runtime parity.
