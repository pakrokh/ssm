"""Core Health and Reset API endpoints."""

from datetime import datetime, timedelta
import asyncio
import logging
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import CoreResetConfig, Node, Tunnel
from app.node_client import NodeClient
from app.tunnel_projects import DEFAULT_PROJECT_FOR_CORE, list_tunnel_projects

router = APIRouter()
logger = logging.getLogger(__name__)

LEGACY_RESET_CORES = {"gost", "backhaul", "rathole", "chisel", "frp"}


class CoreHealthResponse(BaseModel):
    core: str
    label: str | None = None
    core_id: str | None = None
    nodes_status: dict[str, dict[str, Any]]
    servers_status: dict[str, dict[str, Any]]


class ResetConfigResponse(BaseModel):
    core: str
    label: str | None = None
    enabled: bool
    interval_minutes: int
    last_reset: datetime | None
    next_reset: datetime | None


class ResetConfigUpdate(BaseModel):
    enabled: bool | None = None
    interval_minutes: int | None = None


def _normalized_text(value: str | None) -> str:
    return (value or "").strip().lower()


def _provider_targets() -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    for provider in list_tunnel_projects():
        targets.append(
            {
                "id": provider["id"],
                "label": provider.get("label") or provider["id"],
                "core": _normalized_text(provider.get("core")),
                "kind": "provider",
            }
        )
    return targets


def _resolve_reset_target(raw_target: str) -> dict[str, Any] | None:
    target = _normalized_text(raw_target)
    if not target:
        return None

    for provider in _provider_targets():
        if provider["id"] == target:
            return provider

    if target in LEGACY_RESET_CORES:
        return {
            "id": target,
            "label": target.capitalize(),
            "core": target,
            "kind": "core",
        }
    return None


def _extract_project_id(tunnel: Tunnel) -> str | None:
    spec = tunnel.spec if isinstance(tunnel.spec, dict) else {}
    raw = spec.get("project_id")
    if raw is None:
        return None
    project_id = _normalized_text(str(raw))
    return project_id or None


def _tunnel_matches_provider(tunnel: Tunnel, provider_target: dict[str, Any]) -> bool:
    provider_core = _normalized_text(provider_target.get("core"))
    tunnel_core = _normalized_text(tunnel.core)
    if tunnel_core != provider_core:
        return False

    project_id = _extract_project_id(tunnel)
    if project_id:
        return project_id == provider_target["id"]

    default_provider = DEFAULT_PROJECT_FOR_CORE.get(tunnel_core)
    return default_provider == provider_target["id"]


def _build_health_targets(active_tunnels: list[Tunnel]) -> list[dict[str, Any]]:
    targets = _provider_targets()
    target_ids = {target["id"] for target in targets}
    active_cores = {_normalized_text(tunnel.core) for tunnel in active_tunnels}

    if "chisel" in active_cores and "chisel" not in target_ids:
        targets.append(
            {
                "id": "chisel",
                "label": "Chisel",
                "core": "chisel",
                "kind": "core",
            }
        )

    return targets


def _collect_node_ids_for_tunnels(
    tunnels: list[Tunnel], nodes_by_id: dict[str, Node]
) -> tuple[set[str], set[str]]:
    iran_node_ids: set[str] = set()
    foreign_node_ids: set[str] = set()

    def add_node(node_id: Any, forced_role: str | None = None) -> None:
        if not node_id:
            return
        node_id_str = str(node_id)
        node = nodes_by_id.get(node_id_str)
        if not node:
            return

        node_role = _normalized_text(
            forced_role
            or (node.node_metadata.get("role") if node.node_metadata else None)
            or "iran"
        )
        if node_role == "foreign":
            foreign_node_ids.add(node_id_str)
        else:
            iran_node_ids.add(node_id_str)

    for tunnel in tunnels:
        spec = tunnel.spec if isinstance(tunnel.spec, dict) else {}
        add_node(tunnel.iran_node_id, "iran")
        add_node(spec.get("iran_node_id"), "iran")
        add_node(tunnel.foreign_node_id, "foreign")
        add_node(spec.get("foreign_node_id"), "foreign")
        add_node(tunnel.node_id)
        add_node(spec.get("node_id"))

    return iran_node_ids, foreign_node_ids


async def _check_node_connection(
    target_name: str, client: NodeClient, node_id: str, node: Node, role: str
) -> dict[str, Any]:
    connection_status: dict[str, Any] = {
        "status": "failed",
        "error_message": None,
    }

    try:
        response = await client.get_tunnel_status(node_id, "")
        if response and response.get("status") == "ok":
            connection_status["status"] = "connected"
        else:
            error_msg = response.get("message", "Node disconnected") if response else "Node not responding"
            if "timeout" in error_msg.lower() or "connection" in error_msg.lower():
                connection_status["status"] = "reconnecting"
            else:
                connection_status["status"] = "failed"
            connection_status["error_message"] = error_msg
    except httpx.ConnectError:
        connection_status["status"] = "connecting"
        connection_status["error_message"] = "Connecting to node..."
    except httpx.TimeoutException:
        connection_status["status"] = "reconnecting"
        connection_status["error_message"] = "Connection timeout"
    except Exception as exc:
        logger.error("Error checking %s node %s health: %s", target_name, node_id, exc)
        connection_status["status"] = "failed"
        connection_status["error_message"] = str(exc)

    return {
        "id": node_id,
        "name": node.name,
        "role": role,
        **connection_status,
    }


@router.get("/health", response_model=list[CoreHealthResponse])
async def get_core_health(request: Request, db: AsyncSession = Depends(get_db)):
    """Get health status for all configured provider targets."""
    del request  # reserved for future contextual logic
    health_data: list[CoreHealthResponse] = []

    nodes_result = await db.execute(select(Node))
    all_nodes = nodes_result.scalars().all()
    nodes_by_id = {node.id: node for node in all_nodes}

    tunnels_result = await db.execute(select(Tunnel).where(Tunnel.status == "active"))
    active_tunnels_all = tunnels_result.scalars().all()

    targets = _build_health_targets(active_tunnels_all)
    client = NodeClient()

    for target in targets:
        if target["kind"] == "provider":
            active_tunnels = [
                tunnel
                for tunnel in active_tunnels_all
                if _tunnel_matches_provider(tunnel, target)
            ]
        else:
            active_tunnels = [
                tunnel
                for tunnel in active_tunnels_all
                if _normalized_text(tunnel.core) == target["core"]
            ]

        iran_node_ids, foreign_node_ids = _collect_node_ids_for_tunnels(active_tunnels, nodes_by_id)

        iran_tasks = [
            _check_node_connection(target["id"], client, node_id, nodes_by_id[node_id], "iran")
            for node_id in sorted(iran_node_ids)
            if node_id in nodes_by_id
        ]
        foreign_tasks = [
            _check_node_connection(target["id"], client, node_id, nodes_by_id[node_id], "foreign")
            for node_id in sorted(foreign_node_ids)
            if node_id in nodes_by_id
        ]

        iran_results = await asyncio.gather(*iran_tasks, return_exceptions=True)
        foreign_results = await asyncio.gather(*foreign_tasks, return_exceptions=True)

        iran_nodes: dict[str, dict[str, Any]] = {}
        foreign_nodes: dict[str, dict[str, Any]] = {}

        for result in iran_results:
            if isinstance(result, Exception):
                continue
            iran_nodes[result["id"]] = result

        for result in foreign_results:
            if isinstance(result, Exception):
                continue
            foreign_nodes[result["id"]] = result

        health_data.append(
            CoreHealthResponse(
                core=target["id"],
                label=target.get("label"),
                core_id=target.get("core"),
                nodes_status=iran_nodes,
                servers_status=foreign_nodes,
            )
        )

    return health_data


@router.get("/reset-config", response_model=list[ResetConfigResponse])
async def get_reset_configs(db: AsyncSession = Depends(get_db)):
    """Get reset timer configuration for provider targets and legacy cores."""
    targets = _provider_targets()
    target_ids = {target["id"] for target in targets}

    existing_result = await db.execute(select(CoreResetConfig))
    existing_configs = {
        _normalized_text(config.core): config for config in existing_result.scalars().all()
    }

    for config_id in list(existing_configs.keys()):
        if config_id in LEGACY_RESET_CORES and config_id not in target_ids:
            targets.append(
                {
                    "id": config_id,
                    "label": config_id.capitalize(),
                    "core": config_id,
                    "kind": "core",
                }
            )
            target_ids.add(config_id)

    created_any = False
    for target in targets:
        target_id = target["id"]
        if target_id not in existing_configs:
            config = CoreResetConfig(core=target_id, enabled=False, interval_minutes=10)
            db.add(config)
            existing_configs[target_id] = config
            created_any = True

    if created_any:
        await db.commit()

    configs: list[ResetConfigResponse] = []
    for target in targets:
        config = existing_configs[target["id"]]
        configs.append(
            ResetConfigResponse(
                core=target["id"],
                label=target.get("label"),
                enabled=bool(config.enabled),
                interval_minutes=int(config.interval_minutes),
                last_reset=config.last_reset,
                next_reset=config.next_reset,
            )
        )

    return configs


@router.put("/reset-config/{core}", response_model=ResetConfigResponse)
async def update_reset_config(
    core: str,
    config_update: ResetConfigUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update reset timer configuration for a provider target or legacy core."""
    target = _resolve_reset_target(core)
    if not target:
        raise HTTPException(status_code=400, detail=f"Invalid core/provider: {core}")

    target_id = target["id"]
    result = await db.execute(select(CoreResetConfig).where(CoreResetConfig.core == target_id))
    config = result.scalar_one_or_none()

    if not config:
        config = CoreResetConfig(core=target_id, enabled=False, interval_minutes=10)
        db.add(config)

    if config_update.interval_minutes is not None and config_update.interval_minutes < 1:
        raise HTTPException(status_code=400, detail="Interval must be at least 1 minute")

    if config_update.enabled is not None:
        config.enabled = config_update.enabled
    if config_update.interval_minutes is not None:
        config.interval_minutes = config_update.interval_minutes

    now = datetime.utcnow()
    if config.enabled:
        reference_time = config.last_reset or now
        next_reset = reference_time + timedelta(minutes=config.interval_minutes)
        if next_reset <= now:
            next_reset = now + timedelta(minutes=config.interval_minutes)
        config.next_reset = next_reset
    else:
        config.next_reset = None

    config.updated_at = now
    await db.commit()
    await db.refresh(config)

    return ResetConfigResponse(
        core=config.core,
        label=target.get("label"),
        enabled=config.enabled,
        interval_minutes=config.interval_minutes,
        last_reset=config.last_reset,
        next_reset=config.next_reset,
    )


@router.post("/reset/{core}")
async def manual_reset_core(core: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Manually reset a provider target (restart servers and clients)."""
    target = _resolve_reset_target(core)
    if not target:
        raise HTTPException(status_code=400, detail=f"Invalid core/provider: {core}")

    target_id = target["id"]

    try:
        result = await db.execute(select(CoreResetConfig).where(CoreResetConfig.core == target_id))
        config = result.scalar_one_or_none()

        reset_time = datetime.utcnow()

        if not config:
            config = CoreResetConfig(core=target_id, enabled=False, interval_minutes=10)
            db.add(config)

        config.last_reset = reset_time
        if config.enabled and config.interval_minutes:
            config.next_reset = reset_time + timedelta(minutes=config.interval_minutes)
        await db.commit()
        await db.refresh(config)

        await _reset_core(target_id, request, db)

        return {
            "status": "success",
            "message": f"{target.get('label', target_id)} reset successfully",
            "last_reset": config.last_reset.isoformat() if config.last_reset else None,
        }
    except Exception as exc:
        logger.error("Error resetting %s: %s", target_id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


async def _reset_core(core: str, app_or_request, db: AsyncSession):
    """Internal reset function; supports provider IDs and legacy core IDs."""
    target = _resolve_reset_target(core)
    if not target:
        logger.warning("Skip reset: unknown core/provider '%s'", core)
        return

    if hasattr(app_or_request, "app"):
        app = app_or_request.app
    else:
        app = app_or_request
    del app  # reserved for future use

    if target["kind"] == "provider":
        result = await db.execute(select(Tunnel).where(Tunnel.status == "active"))
        active_tunnels = [
            tunnel
            for tunnel in result.scalars().all()
            if _tunnel_matches_provider(tunnel, target)
        ]
    else:
        result = await db.execute(
            select(Tunnel).where(Tunnel.core == target["core"], Tunnel.status == "active")
        )
        active_tunnels = result.scalars().all()

    client = NodeClient()

    for tunnel in active_tunnels:
        tunnel_core = _normalized_text(tunnel.core)
        try:
            iran_node = None
            foreign_node = None

            if tunnel.node_id:
                result = await db.execute(select(Node).where(Node.id == tunnel.node_id))
                iran_node = result.scalar_one_or_none()
                if iran_node and iran_node.node_metadata.get("role") != "iran":
                    foreign_node = iran_node
                    iran_node = None

            if not foreign_node:
                result = await db.execute(select(Node))
                all_nodes = result.scalars().all()
                foreign_nodes = [
                    node
                    for node in all_nodes
                    if node.node_metadata and node.node_metadata.get("role") == "foreign"
                ]
                if foreign_nodes:
                    foreign_node = foreign_nodes[0]

            if not iran_node:
                if tunnel.node_id:
                    result = await db.execute(select(Node).where(Node.id == tunnel.node_id))
                    iran_node = result.scalar_one_or_none()
                if not iran_node:
                    result = await db.execute(select(Node))
                    all_nodes = result.scalars().all()
                    iran_nodes = [
                        node
                        for node in all_nodes
                        if node.node_metadata and node.node_metadata.get("role") == "iran"
                    ]
                    if iran_nodes:
                        iran_node = iran_nodes[0]

            if not foreign_node or not iran_node:
                logger.warning("Tunnel %s: Missing foreign or iran node, skipping reset", tunnel.id)
                continue

            server_spec = tunnel.spec.copy() if tunnel.spec else {}
            server_spec["mode"] = "server"

            client_spec = tunnel.spec.copy() if tunnel.spec else {}
            client_spec["mode"] = "client"

            if tunnel_core == "rathole":
                transport = server_spec.get("transport") or server_spec.get("type") or "tcp"
                proxy_port = server_spec.get("remote_port") or server_spec.get("listen_port")
                token = server_spec.get("token")
                if not proxy_port or not token:
                    logger.warning("Tunnel %s: Missing remote_port or token, skipping", tunnel.id)
                    continue

                remote_addr = server_spec.get("remote_addr", "0.0.0.0:23333")
                from app.utils import parse_address_port

                _, control_port, _ = parse_address_port(remote_addr)
                if not control_port:
                    control_port = 23333
                server_spec["bind_addr"] = f"0.0.0.0:{control_port}"
                server_spec["proxy_port"] = proxy_port
                server_spec["transport"] = transport
                server_spec["type"] = transport
                if "websocket_tls" in server_spec:
                    server_spec["websocket_tls"] = server_spec["websocket_tls"]
                elif "tls" in server_spec:
                    server_spec["websocket_tls"] = server_spec["tls"]

                iran_node_ip = iran_node.node_metadata.get("ip_address")
                if not iran_node_ip:
                    logger.warning("Tunnel %s: Iran node has no IP address, skipping", tunnel.id)
                    continue
                transport_lower = transport.lower()
                if transport_lower in ("websocket", "ws"):
                    use_tls = bool(server_spec.get("websocket_tls") or server_spec.get("tls"))
                    protocol = "wss://" if use_tls else "ws://"
                    client_spec["remote_addr"] = f"{protocol}{iran_node_ip}:{control_port}"
                else:
                    client_spec["remote_addr"] = f"{iran_node_ip}:{control_port}"
                client_spec["transport"] = transport
                client_spec["type"] = transport
                client_spec["token"] = token
                if "websocket_tls" in server_spec:
                    client_spec["websocket_tls"] = server_spec["websocket_tls"]
                elif "tls" in server_spec:
                    client_spec["websocket_tls"] = server_spec["tls"]
                local_addr = client_spec.get("local_addr")
                if not local_addr:
                    local_addr = f"{iran_node_ip}:{proxy_port}"
                client_spec["local_addr"] = local_addr

            elif tunnel_core == "chisel":
                listen_port = (
                    server_spec.get("listen_port")
                    or server_spec.get("remote_port")
                    or server_spec.get("server_port")
                )
                if not listen_port:
                    logger.warning("Tunnel %s: Missing listen_port, skipping", tunnel.id)
                    continue

                iran_node_ip = iran_node.node_metadata.get("ip_address")
                if not iran_node_ip:
                    logger.warning("Tunnel %s: Iran node has no IP address, skipping", tunnel.id)
                    continue
                server_control_port = server_spec.get("control_port") or (int(listen_port) + 10000)
                server_spec["server_port"] = server_control_port
                server_spec["reverse_port"] = listen_port
                auth = server_spec.get("auth")
                if auth:
                    server_spec["auth"] = auth
                fingerprint = server_spec.get("fingerprint")
                if fingerprint:
                    server_spec["fingerprint"] = fingerprint

                client_spec["server_url"] = f"http://{iran_node_ip}:{server_control_port}"
                client_spec["reverse_port"] = listen_port
                if auth:
                    client_spec["auth"] = auth
                if fingerprint:
                    client_spec["fingerprint"] = fingerprint
                local_addr = client_spec.get("local_addr")
                if not local_addr:
                    local_addr = f"{iran_node_ip}:{listen_port}"
                client_spec["local_addr"] = local_addr

            elif tunnel_core == "frp":
                bind_port = server_spec.get("bind_port", 7000)
                token = server_spec.get("token")
                server_spec["mode"] = "server"
                server_spec["bind_port"] = bind_port
                if token:
                    server_spec["token"] = token

                iran_node_ip = iran_node.node_metadata.get("ip_address")
                if not iran_node_ip:
                    logger.warning("Tunnel %s: Iran node has no IP address, skipping", tunnel.id)
                    continue
                client_spec["mode"] = "client"
                client_spec["server_addr"] = iran_node_ip
                client_spec["server_port"] = bind_port
                if token:
                    client_spec["token"] = token
                tunnel_type = tunnel.type.lower() if tunnel.type else "tcp"
                if tunnel_type not in ["tcp", "udp"]:
                    tunnel_type = "tcp"
                client_spec["type"] = tunnel_type
                local_ip = client_spec.get("local_ip") or iran_node_ip
                local_port = client_spec.get("local_port") or bind_port
                client_spec["local_ip"] = local_ip
                client_spec["local_port"] = local_port

            elif tunnel_core == "backhaul":
                transport = server_spec.get("transport") or server_spec.get("type") or "tcp"
                control_port = (
                    server_spec.get("control_port")
                    or server_spec.get("listen_port")
                    or 3080
                )
                public_port = (
                    server_spec.get("public_port")
                    or server_spec.get("remote_port")
                    or server_spec.get("listen_port")
                )
                target_host = server_spec.get("target_host", "127.0.0.1")
                target_port = server_spec.get("target_port") or public_port
                token = server_spec.get("token")

                if not public_port:
                    logger.warning("Tunnel %s: Missing public_port, skipping", tunnel.id)
                    continue

                bind_ip = server_spec.get("bind_ip") or server_spec.get("listen_ip") or "0.0.0.0"
                server_spec["bind_addr"] = f"{bind_ip}:{control_port}"
                server_spec["transport"] = transport
                server_spec["type"] = transport
                if target_port:
                    target_addr = f"{target_host}:{target_port}"
                    server_spec["ports"] = [f"{public_port}={target_addr}"]
                else:
                    server_spec["ports"] = [str(public_port)]
                if token:
                    server_spec["token"] = token

                iran_node_ip = iran_node.node_metadata.get("ip_address")
                if not iran_node_ip:
                    logger.warning("Tunnel %s: Iran node has no IP address, skipping", tunnel.id)
                    continue
                transport_lower = transport.lower()
                if transport_lower in ("ws", "wsmux"):
                    use_tls = bool(
                        server_spec.get("tls_cert")
                        or server_spec.get("server_options", {}).get("tls_cert")
                    )
                    protocol = "wss://" if use_tls else "ws://"
                    client_spec["remote_addr"] = f"{protocol}{iran_node_ip}:{control_port}"
                else:
                    client_spec["remote_addr"] = f"{iran_node_ip}:{control_port}"
                client_spec["transport"] = transport
                client_spec["type"] = transport
                if token:
                    client_spec["token"] = token

            if not iran_node.node_metadata.get("api_address"):
                iran_node.node_metadata["api_address"] = (
                    f"http://{iran_node.node_metadata.get('ip_address', iran_node.fingerprint)}:"
                    f"{iran_node.node_metadata.get('api_port', 8888)}"
                )
                await db.commit()

            logger.info(
                "Restarting tunnel %s: applying server config to iran node %s",
                tunnel.id,
                iran_node.id,
            )
            server_response = await client.send_to_node(
                node_id=iran_node.id,
                endpoint="/api/agent/tunnels/apply",
                data={
                    "tunnel_id": tunnel.id,
                    "core": tunnel_core,
                    "type": tunnel.type,
                    "spec": server_spec,
                },
            )

            if server_response.get("status") == "error":
                error_msg = server_response.get("message", "Unknown error from iran node")
                logger.error(
                    "Failed to restart tunnel %s on iran node %s: %s",
                    tunnel.id,
                    iran_node.id,
                    error_msg,
                )
                continue

            if not foreign_node.node_metadata.get("api_address"):
                foreign_node.node_metadata["api_address"] = (
                    f"http://{foreign_node.node_metadata.get('ip_address', foreign_node.fingerprint)}:"
                    f"{foreign_node.node_metadata.get('api_port', 8888)}"
                )
                await db.commit()

            logger.info(
                "Restarting tunnel %s: applying client config to foreign node %s",
                tunnel.id,
                foreign_node.id,
            )
            client_response = await client.send_to_node(
                node_id=foreign_node.id,
                endpoint="/api/agent/tunnels/apply",
                data={
                    "tunnel_id": tunnel.id,
                    "core": tunnel_core,
                    "type": tunnel.type,
                    "spec": client_spec,
                },
            )

            if client_response.get("status") == "error":
                error_msg = client_response.get("message", "Unknown error from foreign node")
                logger.error(
                    "Failed to restart tunnel %s on foreign node %s: %s",
                    tunnel.id,
                    foreign_node.id,
                    error_msg,
                )
            else:
                logger.info("Successfully restarted tunnel %s on both nodes", tunnel.id)

            await asyncio.sleep(0.5)
        except Exception as exc:
            logger.error("Failed to restart tunnel %s: %s", tunnel.id, exc, exc_info=True)
