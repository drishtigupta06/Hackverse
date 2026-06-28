#!/usr/bin/env python3
"""
RAG engine — Chroma vector store + sentence-transformers embeddings
for CVE/OWASP document retrieval to feed LLM context.
"""
import os
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

CHROMA_PERSIST_DIR = os.path.join(os.path.dirname(__file__), ".chroma_db")
COLLECTION_NAME = "cyberguard_docs"

_client = None
_collection = None
_embedder = None


def _get_embedder():
    global _embedder
    if _embedder is None:
        try:
            from sentence_transformers import SentenceTransformer
            _embedder = SentenceTransformer("all-MiniLM-L6-v2")
            logger.info("[rag] Embedder loaded: all-MiniLM-L6-v2")
        except Exception as e:
            logger.error(f"[rag] Could not load embedder: {e}")
            _embedder = None
    return _embedder


def _get_collection():
    global _client, _collection
    if _collection is not None:
        return _collection
    try:
        import chromadb
        _client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
        _collection = _client.get_or_create_collection(COLLECTION_NAME)
        logger.info(f"[rag] Chroma collection ready: {COLLECTION_NAME}")
    except Exception as e:
        logger.error(f"[rag] Could not initialize Chroma: {e}")
    return _collection


def add_documents(docs: List[Dict[str, str]]) -> bool:
    """
    Add documents to the vector store.
    docs: [{"id": str, "text": str, "metadata": dict}]
    """
    collection = _get_collection()
    embedder = _get_embedder()
    
    if not collection or not embedder:
        logger.warning("[rag] Skipping document add — Chroma or embedder unavailable")
        return False

    try:
        ids = [d["id"] for d in docs]
        texts = [d["text"] for d in docs]
        metas = [d.get("metadata", {}) for d in docs]
        embeddings = embedder.encode(texts).tolist()
        
        collection.add(
            ids=ids,
            documents=texts,
            embeddings=embeddings,
            metadatas=metas,
        )
        logger.info(f"[rag] Added {len(docs)} documents to vector store")
        return True
    except Exception as e:
        logger.error(f"[rag] Failed to add documents: {e}")
        return False


def retrieve(query: str, k: int = 5) -> List[str]:
    """
    Retrieve k most relevant documents for the given query.
    Returns list of document text strings.
    """
    collection = _get_collection()
    embedder = _get_embedder()
    
    if not collection or not embedder:
        logger.warning("[rag] Retrieval unavailable — Chroma or embedder missing")
        return []

    try:
        query_emb = embedder.encode([query]).tolist()
        results = collection.query(
            query_embeddings=query_emb,
            n_results=min(k, collection.count()),
        )
        docs = results.get("documents", [[]])[0]
        logger.info(f"[rag] Retrieved {len(docs)} docs for query: {query[:60]}")
        return docs
    except Exception as e:
        logger.error(f"[rag] Retrieval failed: {e}")
        return []


def ingest_cve_records(cve_records: List[Dict]) -> bool:
    """Ingest a list of CVE dicts from threat_intel into the vector store."""
    docs = []
    for rec in cve_records:
        cve_id = rec.get("cve_id", "")
        desc = rec.get("description", "")
        if not cve_id or not desc:
            continue
        text = f"{cve_id}: {desc}"
        docs.append({
            "id": cve_id,
            "text": text,
            "metadata": {
                "cve_id": cve_id,
                "cvss_score": str(rec.get("cvss_score", "")),
                "source": "nvd",
            },
        })
    return add_documents(docs) if docs else False


def ingest_owasp_basics() -> bool:
    """Seed the vector store with OWASP Top 10 one-liners."""
    owasp_docs = [
        {"id": "owasp_a01", "text": "A01 Broken Access Control: Restrictions on authenticated users not properly enforced. Attackers can exploit flaws to access unauthorized functionality or data.", "metadata": {"source": "owasp", "category": "A01"}},
        {"id": "owasp_a02", "text": "A02 Cryptographic Failures: Failures related to cryptography that lead to exposure of sensitive data. Use strong encryption like AES-256 and TLS 1.3.", "metadata": {"source": "owasp", "category": "A02"}},
        {"id": "owasp_a03", "text": "A03 Injection: SQL, NoSQL, OS, LDAP injection. Validate and sanitize all user input. Use parameterized queries.", "metadata": {"source": "owasp", "category": "A03"}},
        {"id": "owasp_a04", "text": "A04 Insecure Design: Missing security controls by design. Apply threat modeling, secure design patterns.", "metadata": {"source": "owasp", "category": "A04"}},
        {"id": "owasp_a05", "text": "A05 Security Misconfiguration: Default credentials, unnecessary services enabled. Harden configurations, disable unused features.", "metadata": {"source": "owasp", "category": "A05"}},
        {"id": "owasp_a06", "text": "A06 Vulnerable and Outdated Components: Using components with known vulnerabilities. Keep dependencies updated, use SCA tools.", "metadata": {"source": "owasp", "category": "A06"}},
        {"id": "owasp_a07", "text": "A07 Identification and Authentication Failures: Weak passwords, credential stuffing, missing MFA. Implement strong authentication.", "metadata": {"source": "owasp", "category": "A07"}},
        {"id": "owasp_a08", "text": "A08 Software and Data Integrity Failures: Insecure deserialization, unsigned updates. Verify integrity of software and data.", "metadata": {"source": "owasp", "category": "A08"}},
        {"id": "owasp_a09", "text": "A09 Security Logging and Monitoring Failures: Insufficient logging. Implement centralized logging, alerting, and SIEM integration.", "metadata": {"source": "owasp", "category": "A09"}},
        {"id": "owasp_a10", "text": "A10 Server-Side Request Forgery (SSRF): Force server to make requests to internal resources. Validate and sanitize all user-supplied URLs.", "metadata": {"source": "owasp", "category": "A10"}},
        {"id": "cve_log4shell", "text": "CVE-2021-44228 Log4Shell: Critical RCE in Apache Log4j 2. JNDI lookup feature allows remote code execution via specially crafted log messages. CVSS 10.0. Patch to Log4j 2.17.1+.", "metadata": {"source": "nvd", "cve_id": "CVE-2021-44228"}},
        {"id": "cve_eternalblue", "text": "CVE-2017-0144 EternalBlue: Critical SMB vulnerability in Windows. Allows remote code execution via crafted packets to SMBv1. CVSS 9.3. Patch: MS17-010. Disable SMBv1.", "metadata": {"source": "nvd", "cve_id": "CVE-2017-0144"}},
        {"id": "cve_shellshock", "text": "CVE-2014-6271 Shellshock: Bash vulnerability allowing command injection via environment variables in CGI scripts. CVSS 10.0. Update bash immediately.", "metadata": {"source": "nvd", "cve_id": "CVE-2014-6271"}},
        {"id": "cve_heartbleed", "text": "CVE-2014-0160 Heartbleed: OpenSSL buffer over-read that exposes memory contents including private keys. CVSS 7.5. Upgrade OpenSSL and reissue certificates.", "metadata": {"source": "nvd", "cve_id": "CVE-2014-0160"}},
        {"id": "cve_apache_path", "text": "CVE-2021-41773 Apache Path Traversal: Path traversal and RCE in Apache HTTP Server 2.4.49. Allows reading files outside document root. CVSS 7.5. Upgrade to Apache 2.4.51+.", "metadata": {"source": "nvd", "cve_id": "CVE-2021-41773"}},
        {"id": "sqli_explain", "text": "SQL Injection: Attacker injects malicious SQL through user input, manipulating database queries. Can lead to data theft, authentication bypass, RCE. Remediation: parameterized queries, ORM, input validation.", "metadata": {"source": "owasp", "category": "sqli"}},
        {"id": "xss_explain", "text": "Cross-Site Scripting (XSS): Attacker injects malicious scripts into web pages viewed by other users. Can steal session cookies, redirect users, deface pages. Remediation: output encoding, CSP headers.", "metadata": {"source": "owasp", "category": "xss"}},
    ]
    return add_documents(owasp_docs)


def ingest_scan_report(records: List[Dict], target: str, scan_label: str = "") -> bool:
    """
    Ingest all vulnerability findings from a scan into the vector store.
    Enables AI to answer specific questions about the scan results.
    """
    docs = []
    for rec in records:
        name = rec.get("name", "Unknown Finding")
        desc = rec.get("description", "")
        severity = rec.get("severity", "info")
        cve = rec.get("cve_id")
        
        # Build document text
        text = f"Vulnerability: {name} "
        if cve: text += f"({cve}) "
        text += f"\nTarget: {target}\nSeverity: {severity}\nDescription: {desc}\n"
        text += f"Remediation: {rec.get('remediation', '')}"
        
        doc_id = f"scan_{scan_label}_{rec.get('host', target)}_{name[:20].replace(' ', '_')}_{cve or ''}"
        docs.append({
            "id": doc_id,
            "text": text,
            "metadata": {
                "source": "scan_report",
                "scan_label": scan_label,
                "target": target,
                "severity": severity,
                "cve_id": cve or "N/A"
            }
        })
    
    if docs:
        logger.info(f"[rag] Ingesting {len(docs)} findings from scan on {target}")
        return add_documents(docs)
    return False


def collection_count() -> int:
    """Return number of documents in vector store."""
    collection = _get_collection()
    return collection.count() if collection else 0
