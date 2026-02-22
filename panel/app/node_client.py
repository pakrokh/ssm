"""Client for panel to communicate with nodes"""
import httpx
import logging
import asyncio
from typing import Dict, Any, Optional, Tuple, List
from sqlalchemy import select
from app.database import AsyncSessionLocal
from app.models import Node, Settings
from app.utils import parse_address_port, format_address_port

logger = logging.getLogger(__name__)


class NodeClient:
    """Client to send requests to nodes via HTTP/HTTPS or FRP"""
    
    def __init__(self):
        self.timeout = httpx.Timeout(30.0)

    def _normalize_http_base(self, address: str) -> str:
        raw = (address or "").strip()
        if not raw:
            return ""
        if not raw.startswith("http://") and not raw.startswith("https://"):
            raw = f"http://{raw}"
        return raw.rstrip("/")

    def _direct_address_candidates(self, node: Node) -> List[str]:
        """Build a prioritized list of direct node API base URLs."""
        metadata = node.node_metadata or {}
        api_port = int(metadata.get("api_port") or 8888)
        ip_address = (metadata.get("ip_address") or "").strip()
        api_address = (metadata.get("api_address") or "").strip()
        candidates: List[str] = []

        if api_address:
            normalized = self._normalize_http_base(api_address)
            if normalized:
                candidates.append(normalized)

                # If api_address points to localhost, try replacing it with node IP.
                host = normalized.split("://", 1)[1]
                parsed_host, parsed_port, _ = parse_address_port(host)
                if parsed_host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"} and ip_address:
                    target_port = parsed_port or api_port
                    replacement = self._normalize_http_base(format_address_port(ip_address, target_port))
                    if replacement:
                        candidates.append(replacement)

        if ip_address:
            candidates.append(self._normalize_http_base(format_address_port(ip_address, api_port)))

        # Last-resort fallback for environments where hostname route works.
        if node.fingerprint:
            candidates.append(self._normalize_http_base(format_address_port(node.fingerprint, api_port)))

        # Also try opposite scheme once for each candidate.
        expanded: List[str] = []
        for base in candidates:
            if not base:
                continue
            expanded.append(base)
            if base.startswith("http://"):
                expanded.append("https://" + base[len("http://"):])
            elif base.startswith("https://"):
                expanded.append("http://" + base[len("https://"):])

        deduped: List[str] = []
        seen = set()
        for base in expanded:
            if base and base not in seen:
                seen.add(base)
                deduped.append(base)
        return deduped
    
    async def _get_frp_settings(self) -> Optional[Dict[str, Any]]:
        """Get FRP communication settings"""
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(Settings).where(Settings.key == "frp"))
            setting = result.scalar_one_or_none()
            if setting and setting.value and setting.value.get("enabled"):
                return setting.value
        return None
    
    async def _get_node_address(self, node: Node) -> Tuple[str, bool]:
        """
        Get node address (direct or via FRP)
        Returns: (address, using_frp)
        """
        frp_settings = await self._get_frp_settings()
        
        if frp_settings and frp_settings.get("enabled"):
            frp_remote_port = node.node_metadata.get("frp_remote_port") if node.node_metadata else None
            if frp_remote_port:
                # Verify FRP server is running before using FRP
                from app.frp_comm_manager import frp_comm_manager
                if not frp_comm_manager.is_running():
                    logger.warning(f"[HTTP] FRP enabled but FRP server not running, falling back to HTTP for node {node.id}")
                    # Fall through to HTTP
                else:
                    # Use FRP - the server is running, tunnel should be available
                    # Note: If connection fails, retry logic will handle it
                    logger.info(f"[FRP] Using FRP tunnel to communicate with node {node.id} (remote_port={frp_remote_port})")
                    return (f"http://127.0.0.1:{frp_remote_port}", True)
            else:
                # FRP is enabled but node hasn't reported its remote port yet (during initial setup)
                logger.warning(f"[HTTP] FRP enabled but node {node.id} has no frp_remote_port yet, temporarily using HTTP")
                logger.warning(f"[HTTP] This should only happen during node registration. After FRP setup, all communication will use FRP.")
        
        # FRP is not enabled or not available - use direct addresses.
        candidates = self._direct_address_candidates(node)
        if not candidates:
            fallback = "http://localhost:8888"
            logger.warning("[HTTP] No direct candidate for node %s, fallback=%s", node.id, fallback)
            return (fallback, False)
        logger.info("[HTTP] Direct candidates for node %s: %s", node.id, candidates)
        return (candidates[0], False)
    
    async def send_to_node(self, node_id: str, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send request to node via HTTPS or FRP
        """
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(Node).where(Node.id == node_id))
            node = result.scalar_one_or_none()
            
            if not node:
                return {"status": "error", "message": f"Node {node_id} not found"}
            
            node_address, using_frp = await self._get_node_address(node)
            
            comm_type = "FRP" if using_frp else "HTTP"
            logger.debug(f"[{comm_type}] Sending request to node {node_id}: {endpoint}")
            
            try:
                # Retry logic for FRP connections which may need a moment to stabilize
                max_retries = 5 if using_frp else 1
                last_error = None

                if using_frp:
                    target_urls = [f"{node_address.rstrip('/')}{endpoint}"]
                else:
                    target_urls = [
                        f"{base.rstrip('/')}{endpoint}" for base in self._direct_address_candidates(node)
                    ] or [f"{node_address.rstrip('/')}{endpoint}"]
                
                for url in target_urls:
                    for attempt in range(max_retries):
                        try:
                            # For FRP, use a new connection each time to avoid connection reuse issues
                            if using_frp and attempt > 0:
                                await asyncio.sleep(2.0)
                                logger.info(
                                    "[FRP] Retry %s/%s for node %s via FRP tunnel",
                                    attempt + 1,
                                    max_retries,
                                    node_id,
                                )

                            async with httpx.AsyncClient(
                                timeout=self.timeout,
                                verify=False,
                                limits=httpx.Limits(max_keepalive_connections=0 if using_frp else 5),
                            ) as client:
                                response = await client.post(url, json=data)
                                response.raise_for_status()

                                if not using_frp:
                                    # Persist the working address for future requests.
                                    working_base = url[: -len(endpoint)].rstrip("/")
                                    current_api = self._normalize_http_base(
                                        (node.node_metadata or {}).get("api_address", "")
                                    )
                                    if working_base and working_base != current_api:
                                        from sqlalchemy.orm.attributes import flag_modified

                                        node.node_metadata = dict(node.node_metadata or {})
                                        node.node_metadata["api_address"] = working_base
                                        flag_modified(node, "node_metadata")
                                        await session.commit()
                                        await session.refresh(node)
                                        logger.info(
                                            "[HTTP] Updated node %s api_address -> %s",
                                            node.id,
                                            working_base,
                                        )
                                return response.json()
                        except httpx.RequestError as e:
                            last_error = e
                            if attempt < max_retries - 1:
                                if not using_frp:
                                    await asyncio.sleep(0.3)
                                continue
                            # Try next URL candidate
                            break

                error_msg = f"Network error: {str(last_error)}"
                if using_frp:
                    url = target_urls[0]
                    remote_port = url.split(":")[-1].split("/")[0] if ":" in url else "unknown"
                    error_msg += (
                        f" (FRP tunnel connection failed after {max_retries} attempts. "
                        f"The panel may not be able to reach FRP server on 127.0.0.1:{remote_port}. "
                        "Check if panel and FRP server are in the same network namespace, or check FRP server logs.)"
                    )
                else:
                    error_msg += f" (tried: {', '.join(target_urls)})"
                return {"status": "error", "message": error_msg}
                
                # Should not reach here, but just in case
                return {"status": "error", "message": f"Network error: {str(last_error)}"}
            except httpx.HTTPStatusError as e:
                try:
                    error_detail = e.response.json().get("detail", str(e))
                except:
                    error_detail = str(e)
                return {"status": "error", "message": f"Node error (HTTP {e.response.status_code}): {error_detail}"}
            except Exception as e:
                return {"status": "error", "message": f"Error: {str(e)}"}
    
    async def get_tunnel_status(self, node_id: str, tunnel_id: str = "") -> Dict[str, Any]:
        """Get tunnel status from node"""
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(Node).where(Node.id == node_id))
            node = result.scalar_one_or_none()
            
            if not node:
                return {"status": "error", "message": f"Node {node_id} not found"}
            
            node_address, using_frp = await self._get_node_address(node)
            
            comm_type = "FRP" if using_frp else "HTTP"
            logger.debug(f"[{comm_type}] Getting tunnel status from node {node_id}")
            
            try:
                timeout = httpx.Timeout(3.0, connect=2.0)
                if using_frp:
                    target_urls = [f"{node_address.rstrip('/')}/api/agent/status"]
                else:
                    target_urls = [
                        f"{base.rstrip('/')}/api/agent/status"
                        for base in self._direct_address_candidates(node)
                    ] or [f"{node_address.rstrip('/')}/api/agent/status"]

                last_error: Exception | None = None
                for url in target_urls:
                    try:
                        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                            response = await client.get(url)
                            response.raise_for_status()

                            if not using_frp:
                                working_base = url[: -len("/api/agent/status")].rstrip("/")
                                current_api = self._normalize_http_base(
                                    (node.node_metadata or {}).get("api_address", "")
                                )
                                if working_base and working_base != current_api:
                                    from sqlalchemy.orm.attributes import flag_modified

                                    node.node_metadata = dict(node.node_metadata or {})
                                    node.node_metadata["api_address"] = working_base
                                    flag_modified(node, "node_metadata")
                                    await session.commit()
                                    await session.refresh(node)
                                    logger.info(
                                        "[HTTP] Updated node %s api_address -> %s",
                                        node.id,
                                        working_base,
                                    )
                            return response.json()
                    except httpx.RequestError as e:
                        last_error = e
                        continue
                return {"status": "error", "message": f"Network error: {str(last_error)}"}
            except httpx.RequestError as e:
                return {"status": "error", "message": f"Network error: {str(e)}"}
            except httpx.HTTPStatusError as e:
                try:
                    error_detail = e.response.json().get("detail", str(e))
                except:
                    error_detail = str(e)
                return {"status": "error", "message": f"Node error (HTTP {e.response.status_code}): {error_detail}"}
            except Exception as e:
                return {"status": "error", "message": f"Error: {str(e)}"}
    
    async def apply_tunnel(self, node_id: str, tunnel_data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply tunnel to node"""
        return await self.send_to_node(node_id, "/api/agent/tunnels/apply", tunnel_data)
