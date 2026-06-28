#!/usr/bin/env python3
"""
Attack graph builder — constructs a networkx graph from scan results
and serializes it for D3.js visualization in the frontend.
Also writes to Neo4j if configured.
"""
import logging
from typing import List, Dict, Any

import networkx as nx

logger = logging.getLogger(__name__)


def build_attack_graph(scan_id: str, vulnerabilities: List[Dict[str, Any]]) -> Dict:
    """
    Build an attack path graph from normalized vulnerability records.
    
    Graph structure:
      ATTACKER → HOST → PORT/SERVICE → VULNERABILITY → EXPLOIT
    
    Returns serializable dict with nodes + edges for D3.js.
    """
    G = nx.DiGraph()
    
    # Root attacker node
    attacker_id = "attacker_0"
    G.add_node(attacker_id, label="Attacker", type="attacker", severity=None)

    hosts_seen = set()
    ports_seen = set()
    vulns_seen = set()

    for vuln in vulnerabilities:
        host = vuln.get("host", "unknown")
        port = vuln.get("port")
        service = vuln.get("service", "")
        severity = vuln.get("severity", "info")
        cve_id = vuln.get("cve_id")
        name = vuln.get("name", "Unknown")

        # Host node
        host_id = f"host_{host.replace('.', '_')}"
        if host not in hosts_seen:
            hosts_seen.add(host)
            G.add_node(host_id, label=host, type="host", severity=None, data={"ip": host})
            G.add_edge(attacker_id, host_id, label="reaches")

        # Port/Service node
        if port:
            port_id = f"port_{host.replace('.', '_')}_{port}"
            if port_id not in ports_seen:
                ports_seen.add(port_id)
                G.add_node(
                    port_id, 
                    label=f"{port}/{service or 'unknown'}",
                    type="service",
                    severity=None,
                    data={"port": port, "service": service},
                )
                G.add_edge(host_id, port_id, label="exposes")
            parent_id = port_id
        else:
            parent_id = host_id

        # Vulnerability node
        vuln_label = cve_id or name[:30]
        vuln_node_id = f"vuln_{scan_id}_{vuln_label.replace('-', '_').replace(' ', '_')[:40]}"
        
        if vuln_node_id not in vulns_seen:
            vulns_seen.add(vuln_node_id)
            G.add_node(
                vuln_node_id,
                label=vuln_label,
                type="vulnerability",
                severity=severity,
                data={
                    "name": name,
                    "cve_id": cve_id,
                    "severity": severity,
                    "description": vuln.get("description", "")[:200],
                },
            )
            G.add_edge(parent_id, vuln_node_id, label="vulnerable_to")

            # Exploit node if available
            if vuln.get("exploit_available"):
                exploit_id = f"exploit_{vuln_node_id}"
                G.add_node(
                    exploit_id,
                    label=f"Exploit for {vuln_label}",
                    type="exploit",
                    severity="critical",
                    data={"cve_id": cve_id},
                )
                G.add_edge(vuln_node_id, exploit_id, label="leads_to")

    # Serialize to JSON-friendly dict
    nodes = []
    for node_id, attrs in G.nodes(data=True):
        nodes.append({
            "id": node_id,
            "label": attrs.get("label", node_id),
            "type": attrs.get("type", "unknown"),
            "severity": attrs.get("severity"),
            "data": attrs.get("data", {}),
        })

    edges = []
    for src, tgt, attrs in G.edges(data=True):
        edges.append({
            "source": src,
            "target": tgt,
            "label": attrs.get("label", ""),
        })

    logger.info(f"[graph] Built graph: {len(nodes)} nodes, {len(edges)} edges for scan {scan_id}")
    return {"scan_id": scan_id, "nodes": nodes, "edges": edges}


def get_attack_paths(graph_data: Dict) -> List[List[str]]:
    """Find all paths from attacker to vulnerabilities/exploits."""
    G = nx.DiGraph()
    for node in graph_data["nodes"]:
        G.add_node(node["id"])
    for edge in graph_data["edges"]:
        G.add_edge(edge["source"], edge["target"])

    paths = []
    exploit_nodes = [n["id"] for n in graph_data["nodes"] if n["type"] in ("exploit", "vulnerability") and n.get("severity") in ("critical", "high")]
    
    for target in exploit_nodes[:5]:  # Top 5 high-severity paths
        try:
            path = nx.shortest_path(G, "attacker_0", target)
            paths.append(path)
        except nx.NetworkXNoPath:
            pass

    return paths


def try_write_neo4j(graph_data: Dict) -> bool:
    """Optionally write graph to Neo4j if configured."""
    try:
        from neo4j import GraphDatabase
        import config
        
        if not config.NEO4J_PASS:
            return False
        
        driver = GraphDatabase.driver(config.NEO4J_URL, auth=(config.NEO4J_USER, config.NEO4J_PASS))
        scan_id = graph_data["scan_id"]
        
        with driver.session() as session:
            # Create nodes
            for node in graph_data["nodes"]:
                session.run(
                    f"MERGE (n:{node['type'].capitalize()} {{id: $id}}) "
                    "SET n.label = $label, n.severity = $severity, n.scan_id = $scan_id",
                    id=node["id"], label=node["label"], severity=node.get("severity"), scan_id=scan_id
                )
            # Create edges
            for edge in graph_data["edges"]:
                rel_type = edge["label"].upper().replace(" ", "_").replace("-", "_") or "CONNECTS"
                session.run(
                    f"MATCH (a {{id: $src}}), (b {{id: $tgt}}) MERGE (a)-[:{rel_type}]->(b)",
                    src=edge["source"], tgt=edge["target"]
                )
        driver.close()
        logger.info(f"[graph] Neo4j updated for scan {scan_id}")
        return True
    except Exception as e:
        logger.warning(f"[graph] Neo4j write skipped: {e}")
        return False
