import os
from dotenv import load_dotenv

load_dotenv()

# MongoDB
MONGO_URL = os.getenv("MONGO_URL", "mongodb://admin:cyberguard2024@localhost:27017/cyberguard?authSource=admin")
MONGO_DB = os.getenv("MONGO_DB", "cyberguard")

# Redis
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Neo4j
NEO4J_URL = os.getenv("NEO4J_URL", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "cyberguard2024")

# MinIO
MINIO_URL = os.getenv("MINIO_URL", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "cyberguard2024")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "cyberguard-raw")

# Acunetix
ACUNETIX_URL = os.getenv("ACUNETIX_URL", "https://localhost:3443")
ACUNETIX_KEY = os.getenv("ACUNETIX_KEY", "")

# LLM
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://90.92.253.107:9000/v1")
LLM_API_KEY = os.getenv("LLM_API_KEY", "ollama")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen2.5:7b")

# JWT
JWT_SECRET = os.getenv("JWT_SECRET", "cyberguard-secret-key-change-in-production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "1440"))

# NVD
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# Nmap
NMAP_BIN = os.getenv("NMAP_BIN", "/usr/bin/nmap")
