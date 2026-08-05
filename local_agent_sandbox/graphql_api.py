"""
GraphQL-based "God Mode" Observability API Engine (AC3).
Provides real-time cross-sandbox state, filesystem mutations, network packets,
mesh topology queries, and administrative control mutations.
"""

import json
import re
from typing import Dict, List, Optional, Any, Union
from .orchestrator import UniverseOrchestrator, Universe, UniverseStatus
from .mesh import MeshNetworkManager


class GodModeGraphQLAPI:
    """
    GraphQL Execution Engine providing real-time "God Mode" observability
    and orchestration control over all sandboxes in the ecology.
    """

    def __init__(self, orchestrator: UniverseOrchestrator, mesh_manager: Optional[MeshNetworkManager] = None):
        self.orchestrator = orchestrator
        self.mesh_manager = mesh_manager or MeshNetworkManager()

    def execute(self, query_string: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes a GraphQL query or mutation string and returns standard GraphQL response format.
        Example: { "data": { ... }, "errors": [ ... ] }
        """
        variables = variables or {}
        cleaned = self._clean_query(query_string)

        try:
            if cleaned.startswith("mutation"):
                data = self._handle_mutation(cleaned, variables)
            else:
                data = self._handle_query(cleaned, variables)
            return {"data": data}
        except Exception as e:
            return {"data": None, "errors": [{"message": str(e)}]}

    def _clean_query(self, query: str) -> str:
        lines = [line.split("#")[0] for line in query.strip().splitlines()]
        return " ".join(" ".join(lines).split())

    def _extract_args(self, field_call: str) -> Dict[str, Any]:
        args = {}
        match = re.search(r'\((.*?)\)', field_call)
        if not match:
            return args
        
        arg_str = match.group(1)
        pairs = re.findall(r'(\w+)\s*:\s*("(?:[^"\\]|\\.)*"|\d+\.\d+|\d+|\w+)', arg_str)
        for key, val in pairs:
            if val.startswith('"') and val.endswith('"'):
                args[key] = val[1:-1]
            elif val.isdigit():
                args[key] = int(val)
            elif val == "true":
                args[key] = True
            elif val == "false":
                args[key] = False
            else:
                try:
                    args[key] = float(val)
                except ValueError:
                    args[key] = val
        return args

    def _handle_query(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        result = {}

        if "systemMetrics" in query or "system_metrics" in query:
            result["systemMetrics"] = self.orchestrator.get_system_metrics()

        if "meshTopology" in query or "mesh_topology" in query:
            result["meshTopology"] = self.mesh_manager.get_mesh_topology()

        if "universes" in query:
            args = self._extract_args(query)
            limit = variables.get("limit") or args.get("limit", 100)
            offset = variables.get("offset") or args.get("offset", 0)
            status_str = variables.get("status") or args.get("status")

            status = UniverseStatus(status_str) if status_str else None
            universes = self.orchestrator.list_universes(status=status, limit=limit, offset=offset)
            result["universes"] = [u.to_dict() for u in universes]

        if "universe(" in query or "universe (" in query:
            args = self._extract_args(query)
            uv_id = variables.get("id") or args.get("id")
            if uv_id:
                uv = self.orchestrator.get_universe(str(uv_id))
                if uv:
                    res = uv.to_dict()
                    res["logs"] = uv.logs
                    res["filesystem_changes"] = [
                        {
                            "timestamp": fc.timestamp,
                            "path": fc.path,
                            "action": fc.action,
                            "size_bytes": fc.size_bytes,
                        }
                        for fc in uv.filesystem_changes
                    ]
                    res["network_packets"] = [
                        {
                            "timestamp": np.timestamp,
                            "source_id": np.source_id,
                            "target_id": np.target_id,
                            "protocol": np.protocol,
                            "payload_bytes": np.payload_bytes,
                        }
                        for np in uv.network_packets
                    ]
                    result["universe"] = res
                else:
                    result["universe"] = None

        if "filesystemChanges" in query:
            args = self._extract_args(query)
            uv_id = variables.get("universeId") or args.get("universeId")
            changes = []
            if uv_id:
                uv = self.orchestrator.get_universe(str(uv_id))
                if uv:
                    changes = [
                        {
                            "timestamp": c.timestamp,
                            "path": c.path,
                            "action": c.action,
                            "size_bytes": c.size_bytes,
                        }
                        for c in uv.filesystem_changes
                    ]
            else:
                for u in self.orchestrator.universes.values():
                    for c in u.filesystem_changes:
                        changes.append({
                            "universe_id": u.id,
                            "timestamp": c.timestamp,
                            "path": c.path,
                            "action": c.action,
                            "size_bytes": c.size_bytes,
                        })
            result["filesystemChanges"] = changes

        if "networkTraffic" in query:
            args = self._extract_args(query)
            uv_id = variables.get("universeId") or args.get("universeId")
            packets = []
            if uv_id:
                uv = self.orchestrator.get_universe(str(uv_id))
                if uv:
                    packets = [
                        {
                            "timestamp": p.timestamp,
                            "source_id": p.source_id,
                            "target_id": p.target_id,
                            "protocol": p.protocol,
                            "payload_bytes": p.payload_bytes,
                        }
                        for p in uv.network_packets
                    ]
            else:
                for u in self.orchestrator.universes.values():
                    for p in u.network_packets:
                        packets.append({
                            "timestamp": p.timestamp,
                            "source_id": p.source_id,
                            "target_id": p.target_id,
                            "protocol": p.protocol,
                            "payload_bytes": p.payload_bytes,
                        })
            result["networkTraffic"] = packets

        return result

    def _handle_mutation(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        result = {}

        if "createUniverses" in query:
            args = self._extract_args(query)
            count = variables.get("count") or args.get("count", 10)
            prefix = variables.get("namePrefix") or args.get("namePrefix", "godmode-node")
            nodes = self.orchestrator.create_universes_batch(count=count, name_prefix=prefix)
            result["createUniverses"] = [n.to_dict() for n in nodes]
        elif "createUniverse" in query or "create_universe" in query:
            args = self._extract_args(query)
            name = variables.get("name") or args.get("name", "agent-universe")
            uv = self.orchestrator.create_universe(name=name)
            result["createUniverse"] = uv.to_dict()

        if "destroyUniverse" in query:
            args = self._extract_args(query)
            uv_id = variables.get("id") or args.get("id")
            success = False
            if uv_id:
                success = self.orchestrator.destroy_universe(str(uv_id))
            result["destroyUniverse"] = success

        if "meshUniverses" in query:
            args = self._extract_args(query)
            src_id = variables.get("sourceId") or args.get("sourceId")
            tgt_id = variables.get("targetId") or args.get("targetId")
            if src_id and tgt_id:
                src_uv = self.orchestrator.get_universe(str(src_id))
                tgt_uv = self.orchestrator.get_universe(str(tgt_id))
                if src_uv and tgt_uv:
                    channel = self.mesh_manager.negotiate_channel(src_uv, tgt_uv)
                    if channel:
                        result["meshUniverses"] = {
                            "channel_id": channel.channel_id,
                            "source_id": channel.source_id,
                            "target_id": channel.target_id,
                            "active": channel.is_active,
                        }
                    else:
                        result["meshUniverses"] = None
                else:
                    result["meshUniverses"] = None

        return result
