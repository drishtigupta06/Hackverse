from motor.motor_asyncio import AsyncIOMotorClient
import asyncio
import uuid
from datetime import datetime

import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("MONGO_DB", "cyberguard")

async def seed_demo_data():
    client = AsyncIOMotorClient(MONGO_URL)
    db = client[DB_NAME]
    
    # Fake Dark Web Leaks
    leaks = [
        {
            "scan_id": str(uuid.uuid4()),
            "target_domain": "juice-shop.herokuapp.com",
            "status": "completed",
            "findings": [
                {"source": "RaidForums", "title": "Admin Dashboard Breach", "description": "Admin credentials found in cleartext. email: admin@juice-sh.op, pass: admin123", "severity": "critical", "date_found": "2024-03-01"},
                {"source": "BreachComp", "title": "Developer Logs", "description": "API keys for AWS dev instance exposed in snippet.", "severity": "high", "date_found": "2024-02-15"}
            ],
            "created_at": datetime.utcnow().isoformat(),
            "completed_at": datetime.utcnow().isoformat()
        }
    ]
    await db.leak_reports.insert_many(leaks)
    
    print("✅ Demo leak data seeded.")
    client.close()

if __name__ == "__main__":
    asyncio.run(seed_demo_data())
