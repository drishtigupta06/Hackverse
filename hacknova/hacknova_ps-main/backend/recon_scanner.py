import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import List, Dict, Any
from models import ReconAsset, AssetType, ScanStatus

logger = logging.getLogger(__name__)

class ReconScanner:
    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.assets: Dict[str, ReconAsset] = {}

    async def run_subfinder(self) -> List[Dict[str, Any]]:
        """Run subfinder for fast passive discovery."""
        cmd = ["subfinder", "-d", self.target_domain, "-json", "-silent"]
        logger.info(f"[recon] Running subfinder for {self.target_domain}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            results = []
            if stdout:
                for line in stdout.decode().splitlines():
                    if line.strip():
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            return results
        except Exception as e:
            logger.error(f"[recon] subfinder failed: {e}")
            return []

    async def run_amass(self) -> List[Dict[str, Any]]:
        """Run amass enum for thorough discovery."""
        # Using passive mode for speed in demo/standard runs, can be toggled
        cmd = ["amass", "enum", "-passive", "-d", self.target_domain, "-json", "stdout", "-silent"]
        logger.info(f"[recon] Running amass for {self.target_domain}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            results = []
            if stdout:
                for line in stdout.decode().splitlines():
                    if line.strip():
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            return results
        except Exception as e:
            logger.error(f"[recon] amass failed: {e}")
            return []

    async def execute_discovery(self) -> List[ReconAsset]:
        """Orchestrate both tools and merge results."""
        sub_task = asyncio.create_task(self.run_subfinder())
        amass_task = asyncio.create_task(self.run_amass())
        
        sub_results, amass_results = await asyncio.gather(sub_task, amass_task)
        
        # Merge subfinder results
        for item in sub_results:
            host = item.get("host")
            if not host: continue
            
            if host not in self.assets:
                self.assets[host] = ReconAsset(
                    domain=host,
                    asset_type=AssetType.subdomain,
                    source=["subfinder"],
                    ip_addresses=[item.get("ip")] if item.get("ip") else []
                )
            else:
                if "subfinder" not in self.assets[host].source:
                    self.assets[host].source.append("subfinder")
                if item.get("ip") and item.get("ip") not in self.assets[host].ip_addresses:
                    self.assets[host].ip_addresses.append(item.get("ip"))

        # Merge amass results
        for item in amass_results:
            name = item.get("name")
            if not name: continue
            
            ips = [addr.get("address") for addr in item.get("addresses", []) if addr.get("address")]
            
            if name not in self.assets:
                self.assets[name] = ReconAsset(
                    domain=name,
                    asset_type=AssetType.subdomain,
                    source=["amass"],
                    ip_addresses=ips
                )
            else:
                if "amass" not in self.assets[name].source:
                    self.assets[name].source.append("amass")
                for ip in ips:
                    if ip not in self.assets[name].ip_addresses:
                        self.assets[name].ip_addresses.append(ip)
                        
        return list(self.assets.values())

async def run_recon_job(recon_id: str, target_domain: str, db):
    """Entry point for background task."""
    logger.info(f"[recon] Starting job {recon_id} for {target_domain}")
    
    await db.recon_jobs.update_one(
        {"recon_id": recon_id},
        {"$set": {"status": ScanStatus.running, "started_at": datetime.utcnow()}}
    )
    
    try:
        scanner = ReconScanner(target_domain)
        assets = await scanner.execute_discovery()
        
        # Save assets to DB
        if assets:
            # Add recon_id link
            for asset in assets:
                asset_dict = asset.dict()
                asset_dict["scan_id"] = recon_id
                await db.recon_assets.insert_one(asset_dict)
                
        await db.recon_jobs.update_one(
            {"recon_id": recon_id},
            {"$set": {
                "status": ScanStatus.completed,
                "completed_at": datetime.utcnow(),
                "asset_count": len(assets)
            }}
        )
        logger.info(f"[recon] Job {recon_id} completed. Found {len(assets)} assets.")
        
    except Exception as e:
        logger.error(f"[recon] Job {recon_id} failed: {e}")
        await db.recon_jobs.update_one(
            {"recon_id": recon_id},
            {"$set": {"status": ScanStatus.failed, "error": str(e)}}
        )
