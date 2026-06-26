#!/usr/bin/env python3
"""
Nmap scanner module — runs nmap -sV --script vuln and parses XML output.
Adapted from comolho-scope-extractor/nmap_scanner.py.
"""
import subprocess
import xml.etree.ElementTree as ET
import os
import time
import logging
from typing import List, Dict, Any, Optional

import config

logger = logging.getLogger(__name__)


def run_nmap_scan(target: str, ports: str = None, timeout: int = 600) -> List[Dict[str, Any]]:
    """
    Run nmap against target and return list of host/port/service dicts.
    
    Returns:
        [{"host": str, "port": int, "protocol": str, "state": str,
          "service": str, "version": str, "scripts": str}]
    """
    xml_file = f"/tmp/cyberguard_nmap_{target.replace('/', '_')}_{int(time.time())}.xml"
    
    cmd = [
        config.NMAP_BIN,
        "-sV",
        "--script", "vuln,default",
        "-F",              # Fast: top 100 ports
        "-oX", xml_file,
    ]
    if ports:
        cmd += ["-p", ports]
    cmd.append(target)

    logger.info(f"[nmap] Running: {' '.join(cmd)}")

    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.warning(f"[nmap] Timeout scanning {target}")
        return []
    except Exception as e:
        logger.error(f"[nmap] Error scanning {target}: {e}")
        return []

    if not os.path.exists(xml_file):
        logger.warning(f"[nmap] No XML output for {target}")
        return []

    results = _parse_nmap_xml(xml_file, target)
    
    try:
        os.remove(xml_file)
    except Exception:
        pass
    
    return results


def _parse_nmap_xml(xml_file: str, fallback_host: str) -> List[Dict[str, Any]]:
    """Parse nmap XML output file into list of result dicts."""
    results = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        for host_el in root.findall("host"):
            # Get IP or hostname
            addr_el = host_el.find("address[@addrtype='ipv4']")
            host = addr_el.get("addr") if addr_el is not None else fallback_host
            
            hostname_el = host_el.find(".//hostname")
            hostname = hostname_el.get("name") if hostname_el is not None else host

            status_el = host_el.find("status")
            status = status_el.get("state", "unknown") if status_el is not None else "unknown"

            for port_el in host_el.findall(".//port"):
                port_id = int(port_el.get("portid", 0))
                protocol = port_el.get("protocol", "tcp")

                state_el = port_el.find("state")
                state = state_el.get("state", "unknown") if state_el is not None else "unknown"

                service_el = port_el.find("service")
                service = ""
                version = ""
                if service_el is not None:
                    service = service_el.get("name", "")
                    product = service_el.get("product", "")
                    ver = service_el.get("version", "")
                    extra = service_el.get("extrainfo", "")
                    version = " ".join(filter(None, [product, ver, extra])).strip()

                # Script outputs (vuln data)
                scripts = []
                for script_el in port_el.findall("script"):
                    sid = script_el.get("id", "")
                    sout = script_el.get("output", "").strip()
                    if sout:
                        scripts.append(f"[{sid}]\n{sout}")
                script_out = "\n\n".join(scripts)

                results.append({
                    "host": host,
                    "hostname": hostname,
                    "status": status,
                    "port": port_id,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "version": version,
                    "scripts": script_out,
                })

    except Exception as e:
        logger.error(f"[nmap] XML parse error: {e}")

    logger.info(f"[nmap] Parsed {len(results)} port entries from {xml_file}")
    return results
