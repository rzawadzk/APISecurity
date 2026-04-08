"""Service Dependency Graph — Blast Radius Visualization.

Maps which services call which APIs to build a dependency graph.
Identifies orphaned services, critical paths, and blast radius
for outage scenarios.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from .database import Database
from .egress import EgressTracker


@dataclass
class ServiceNode:
    """A node in the dependency graph (a service or API)."""

    name: str
    node_type: str  # "service", "api_endpoint", "third_party"
    host: Optional[str] = None
    endpoint_count: int = 0
    total_calls: int = 0
    error_rate: float = 0.0
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.name,
            "type": self.node_type,
            "host": self.host,
            "endpoint_count": self.endpoint_count,
            "total_calls": self.total_calls,
            "error_rate": round(self.error_rate, 3),
            "metadata": self.metadata,
        }


@dataclass
class ServiceEdge:
    """A directed edge: source --calls--> target."""

    source: str
    target: str
    call_count: int = 0
    methods: set = field(default_factory=set)
    paths: set = field(default_factory=set)
    error_count: int = 0
    avg_latency_ms: Optional[float] = None

    @property
    def error_rate(self) -> float:
        return self.error_count / self.call_count if self.call_count else 0

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "target": self.target,
            "call_count": self.call_count,
            "methods": sorted(self.methods),
            "paths_sample": sorted(list(self.paths)[:5]),
            "error_count": self.error_count,
            "error_rate": round(self.error_rate, 3),
            "avg_latency_ms": round(self.avg_latency_ms, 2) if self.avg_latency_ms else None,
        }


class DependencyGraph:
    """Builds and analyzes service dependency graphs."""

    def __init__(self):
        self.nodes: dict[str, ServiceNode] = {}
        self.edges: dict[tuple[str, str], ServiceEdge] = {}

    def _ensure_node(self, name: str, node_type: str = "service", **kwargs) -> ServiceNode:
        if name not in self.nodes:
            self.nodes[name] = ServiceNode(name=name, node_type=node_type, **kwargs)
        return self.nodes[name]

    def _ensure_edge(self, source: str, target: str) -> ServiceEdge:
        key = (source, target)
        if key not in self.edges:
            self.edges[key] = ServiceEdge(source=source, target=target)
        return self.edges[key]

    def build_from_database(self, db: Database) -> None:
        """Build the graph from the API inventory database."""
        endpoints = db.get_all_endpoints()

        for ep in endpoints:
            # The API endpoint itself is a node
            service_name = ep.service_name or ep.host or "unknown-service"
            api_node = self._ensure_node(
                service_name,
                node_type="service",
                host=ep.host,
            )
            api_node.endpoint_count += 1
            api_node.total_calls += ep.total_calls
            if ep.total_calls > 0:
                api_node.error_rate = (
                    (api_node.error_rate * (api_node.total_calls - ep.total_calls) + ep.error_count)
                    / api_node.total_calls
                )

            # Each consumer is a calling node
            for consumer in ep.consumers:
                consumer_name = self._resolve_consumer_name(consumer)
                consumer_node = self._ensure_node(consumer_name, node_type="service")
                consumer_node.total_calls += ep.total_calls

                # Create edge: consumer -> service
                edge = self._ensure_edge(consumer_name, service_name)
                edge.call_count += ep.total_calls
                edge.methods.add(ep.method)
                edge.paths.add(ep.path_pattern)
                edge.error_count += ep.error_count

    def build_from_egress(self, tracker: EgressTracker) -> None:
        """Add third-party dependencies from egress tracking."""
        for tp in tracker.get_inventory():
            tp_node = self._ensure_node(
                tp.provider_name if tp.provider_name != "Unknown" else tp.host,
                node_type="third_party",
                host=tp.host,
            )
            tp_node.total_calls = tp.total_calls
            tp_node.error_rate = tp.error_rate
            tp_node.metadata["risk_level"] = tp.risk_level.value

            for caller in tp.calling_services:
                caller_name = self._resolve_consumer_name(caller)
                caller_node = self._ensure_node(caller_name, node_type="service")

                edge = self._ensure_edge(caller_name, tp_node.name)
                edge.call_count = tp.total_calls
                edge.methods = tp.methods_seen.copy()
                edge.paths = tp.paths_seen.copy()
                edge.error_count = tp.error_count

    @staticmethod
    def _resolve_consumer_name(consumer: str) -> str:
        """Turn an IP or service identifier into a readable name."""
        if consumer.startswith(("10.", "172.", "192.168.")):
            return f"internal-{consumer}"
        return consumer

    # ── Analysis ──

    def find_orphaned_services(self) -> list[ServiceNode]:
        """Services that have no incoming or outgoing edges."""
        connected = set()
        for (src, tgt) in self.edges:
            connected.add(src)
            connected.add(tgt)

        return [
            node for name, node in self.nodes.items()
            if name not in connected
        ]

    def find_critical_paths(self) -> list[ServiceNode]:
        """Services with the most dependents (highest in-degree)."""
        in_degree: dict[str, int] = defaultdict(int)
        for (src, tgt) in self.edges:
            in_degree[tgt] += 1

        return sorted(
            [self.nodes[name] for name in in_degree if name in self.nodes],
            key=lambda n: in_degree.get(n.name, 0),
            reverse=True,
        )[:10]

    def blast_radius(self, service_name: str) -> dict:
        """Calculate the blast radius if a service goes down.

        Returns all services that would be directly or transitively affected.
        """
        if service_name not in self.nodes:
            return {"affected": [], "depth": 0}

        affected = set()
        visited = set()
        queue = [(service_name, 0)]
        max_depth = 0

        while queue:
            current, depth = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            if current != service_name:
                affected.add(current)
                max_depth = max(max_depth, depth)

            # Find all services that depend on current (reverse edges)
            for (src, tgt) in self.edges:
                if tgt == current and src not in visited:
                    queue.append((src, depth + 1))

        return {
            "service": service_name,
            "affected_services": sorted(affected),
            "affected_count": len(affected),
            "max_depth": max_depth,
        }

    def find_single_points_of_failure(self) -> list[dict]:
        """Find services whose removal would disconnect the graph."""
        spofs = []
        for name in self.nodes:
            radius = self.blast_radius(name)
            if radius["affected_count"] > len(self.nodes) * 0.3:
                spofs.append({
                    "service": name,
                    "affected_count": radius["affected_count"],
                    "affected_percentage": round(
                        radius["affected_count"] / max(len(self.nodes), 1) * 100, 1
                    ),
                })
        return sorted(spofs, key=lambda s: s["affected_count"], reverse=True)

    # ── Export ──

    def to_dict(self) -> dict:
        """Export the full graph as a dictionary."""
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges.values()],
            "stats": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "services": sum(1 for n in self.nodes.values() if n.node_type == "service"),
                "third_parties": sum(1 for n in self.nodes.values() if n.node_type == "third_party"),
            },
        }

    def to_d3_json(self) -> str:
        """Export as D3.js force-directed graph JSON."""
        nodes = []
        for n in self.nodes.values():
            nodes.append({
                "id": n.name,
                "group": {"service": 1, "api_endpoint": 2, "third_party": 3}.get(n.node_type, 0),
                "type": n.node_type,
                "calls": n.total_calls,
                "size": max(5, min(50, n.total_calls // 10 + 5)),
            })

        links = []
        for e in self.edges.values():
            links.append({
                "source": e.source,
                "target": e.target,
                "value": e.call_count,
                "width": max(1, min(10, e.call_count // 100 + 1)),
            })

        return json.dumps({"nodes": nodes, "links": links}, indent=2)

    def to_mermaid(self) -> str:
        """Export as Mermaid diagram syntax."""
        lines = ["graph LR"]

        for n in self.nodes.values():
            shape = {
                "service": f"    {_mermaid_id(n.name)}[{n.name}]",
                "third_party": f"    {_mermaid_id(n.name)}({n.name})",
                "api_endpoint": f"    {_mermaid_id(n.name)}{{{{{n.name}}}}}",
            }.get(n.node_type, f"    {_mermaid_id(n.name)}[{n.name}]")
            lines.append(shape)

        for e in self.edges.values():
            label = f"{e.call_count} calls"
            lines.append(
                f"    {_mermaid_id(e.source)} -->|{label}| {_mermaid_id(e.target)}"
            )

        return "\n".join(lines)


def _mermaid_id(name: str) -> str:
    """Sanitize a name for Mermaid diagram IDs."""
    return re.sub(r'[^A-Za-z0-9_]', '_', name)


import re
