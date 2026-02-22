"""Tunnel provider catalog and helpers."""

from __future__ import annotations

from typing import Any


ROLL_OUT_ORDER = [
    "trusttunnel",
    "paqet",
    "iodine",
    "backhaul_script",
    "icmp_tun",
    "reverse_tls",
    "udp_tun",
    "rathole",
    "frp",
]

TUNNEL_PROJECTS: dict[str, dict[str, Any]] = {
    "trusttunnel": {
        "label": "TrustTunnel",
        "repo": "https://github.com/TrustTunnel/TrustTunnel?tab=readme-ov-file#install-the-endpoint",
        "core": "gost",
        "default_type": "tcp",
        "supported_types": ["tcp", "udp"],
        "default_ports": "443",
        "runtime_mode": "docker_build",
    },
    "paqet": {
        "label": "paqet",
        "repo": "https://github.com/hanselime/paqet",
        "core": "gost",
        "default_type": "tcp",
        "supported_types": ["tcp", "udp"],
        "default_ports": "9999",
        "runtime_mode": "docker_build",
    },
    "iodine": {
        "label": "iodine",
        "repo": "https://github.com/yarrick/iodine",
        "core": "gost",
        "default_type": "udp",
        "supported_types": ["udp", "tcp"],
        "default_ports": "53",
        "runtime_mode": "docker_build",
    },
    "backhaul_script": {
        "label": "Backhaul_script",
        "repo": "https://github.com/Azumi67/Backhaul_script",
        "core": "backhaul",
        "default_type": "tcpmux",
        "supported_types": ["tcp", "udp", "ws", "wsmux", "tcpmux"],
        "default_ports": "443",
        "runtime_mode": "external_script",
    },
    "icmp_tun": {
        "label": "icmp_tun",
        "repo": "https://github.com/Azumi67/icmp_tun",
        "core": "gost",
        "default_type": "udp",
        "supported_types": ["udp", "tcp"],
        "default_ports": "8004",
        "runtime_mode": "external_script",
    },
    "reverse_tls": {
        "label": "Reverse_tls",
        "repo": "https://github.com/Azumi67/Reverse_tls",
        "core": "gost",
        "default_type": "tcp",
        "supported_types": ["tcp", "udp", "ws"],
        "default_ports": "443",
        "runtime_mode": "external_script",
    },
    "udp_tun": {
        "label": "udp_tun",
        "repo": "https://github.com/Azumi67/udp_tun",
        "core": "gost",
        "default_type": "udp",
        "supported_types": ["udp", "tcp"],
        "default_ports": "8004",
        "runtime_mode": "external_script",
    },
    "rathole": {
        "label": "rathole",
        "repo": "https://github.com/rathole-org/rathole",
        "core": "rathole",
        "default_type": "tcp",
        "supported_types": ["tcp", "ws"],
        "default_ports": "443",
        "runtime_mode": "docker_image",
    },
    "frp": {
        "label": "frp",
        "repo": "https://github.com/fatedier/frp",
        "core": "frp",
        "default_type": "tcp",
        "supported_types": ["tcp", "udp"],
        "default_ports": "443",
        "runtime_mode": "docker_image",
    },
}

PROJECT_IDS = set(TUNNEL_PROJECTS.keys())

DEFAULT_PROJECT_FOR_CORE = {
    "gost": "trusttunnel",
    "backhaul": "backhaul_script",
    "rathole": "rathole",
    "frp": "frp",
}


def get_tunnel_project(project_id: str | None) -> dict[str, Any] | None:
    """Return project profile by id."""
    if not project_id:
        return None
    normalized = str(project_id).strip().lower()
    if not normalized:
        return None
    return TUNNEL_PROJECTS.get(normalized)


def resolve_runtime_mode(core: str, spec: dict[str, Any] | None) -> str | None:
    """Resolve runtime mode from payload metadata with core fallback."""
    normalized_spec = dict(spec or {})
    runtime_mode = str(normalized_spec.get("runtime_mode") or "").strip().lower()
    if runtime_mode:
        return runtime_mode

    project_id = normalized_spec.get("project_id")
    project = get_tunnel_project(project_id)
    if project:
        return str(project.get("runtime_mode") or "").strip().lower() or None

    default_project_id = DEFAULT_PROJECT_FOR_CORE.get((core or "").strip().lower())
    default_project = get_tunnel_project(default_project_id)
    if default_project:
        return str(default_project.get("runtime_mode") or "").strip().lower() or None

    return None


def is_external_script_runtime(core: str, spec: dict[str, Any] | None) -> bool:
    """Check whether tunnel should be handled as external script provider."""
    return resolve_runtime_mode(core, spec) == "external_script"


def list_tunnel_projects() -> list[dict[str, Any]]:
    """Return the provider catalog in the fixed rollout order."""
    projects: list[dict[str, Any]] = []
    for index, project_id in enumerate(ROLL_OUT_ORDER, start=1):
        profile = TUNNEL_PROJECTS[project_id]
        projects.append(
            {
                "id": project_id,
                "order": index,
                **profile,
            }
        )
    return projects


def normalize_tunnel_payload(
    core: str,
    tunnel_type: str,
    spec: dict[str, Any] | None,
    *,
    attach_default_project: bool = True,
) -> tuple[str, str, dict[str, Any]]:
    """Normalize and enrich project metadata while keeping runtime compatibility."""
    normalized_spec = dict(spec or {})
    normalized_core = (core or "").strip().lower()
    normalized_type = (tunnel_type or "").strip().lower()

    project_id_raw = normalized_spec.get("project_id")
    project_id = str(project_id_raw).strip().lower() if project_id_raw else ""
    project = TUNNEL_PROJECTS.get(project_id)

    if not project and attach_default_project:
        default_project_id = DEFAULT_PROJECT_FOR_CORE.get(normalized_core)
        if default_project_id:
            project_id = default_project_id
            project = TUNNEL_PROJECTS[project_id]

    if project:
        normalized_core = project["core"]
        if normalized_type not in project["supported_types"]:
            normalized_type = project["default_type"]

        normalized_spec["project_id"] = project_id
        normalized_spec["project_label"] = project["label"]
        normalized_spec["project_repo"] = project["repo"]
        normalized_spec["runtime_mode"] = project["runtime_mode"]

    return normalized_core, normalized_type, normalized_spec
