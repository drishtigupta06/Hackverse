#!/usr/bin/env python3
"""
LLM Chatbot — RAG-augmented LLM for explaining vulnerabilities and CVEs.
Uses OpenAI-compatible API (works with Ollama).
"""
import logging
from typing import List, Optional, Tuple

from openai import OpenAI

import config
import rag_engine

logger = logging.getLogger(__name__)

_client: Optional[OpenAI] = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(
            base_url=config.LLM_BASE_URL,
            api_key=config.LLM_API_KEY,
        )
    return _client


SYSTEM_PROMPT = """You are CyberGuard AI, an expert cybersecurity assistant embedded in a vulnerability analysis platform.

Your job is to:
1. Explain vulnerabilities, CVEs, and attack paths in clear, actionable language
2. Provide CVSS context and severity reasoning
3. Suggest specific remediation steps
4. Answer questions about security concepts (OWASP, network services, exploits)

Always be precise and practical. When discussing a CVE, include:
- What it affects
- How it can be exploited  
- The severity level (CVSS score if known)
- Specific remediation steps

Format your responses with markdown for clarity."""


def ask(question: str, scan_context: Optional[str] = None, k_docs: int = 5) -> Tuple[str, List[str]]:
    """
    Ask the LLM a security question with RAG context.
    
    Args:
        question: User's question
        scan_context: Optional string with relevant scan results
        k_docs: Number of docs to retrieve from vector store
    
    Returns:
        (answer: str, context_used: List[str])
    """
    # Retrieve relevant documents from vector store
    relevant_docs = rag_engine.retrieve(question, k=k_docs)
    
    # Build augmented prompt
    context_parts = []
    
    if relevant_docs:
        context_parts.append("**Relevant knowledge base context:**\n" + "\n---\n".join(relevant_docs[:3]))
    
    if scan_context:
        context_parts.append(f"**Current scan findings:**\n{scan_context}")
    
    user_message = question
    if context_parts:
        user_message = "\n\n".join(context_parts) + f"\n\n**User question:** {question}"

    try:
        client = _get_client()
        response = client.chat.completions.create(
            model=config.LLM_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            temperature=0.3,
            max_tokens=1500,
        )
        answer = response.choices[0].message.content or "I could not generate a response."
        logger.info(f"[llm] Generated answer ({len(answer)} chars) for: {question[:60]}")
        return answer, relevant_docs
    except Exception as e:
        logger.error(f"[llm] LLM call failed: {e}")
        error_answer = (
            f"⚠️ **CyberGuard AI is temporarily unavailable.**\n\n"
            f"Error: `{str(e)}`\n\n"
            f"Please check that the LLM endpoint is running at `{config.LLM_BASE_URL}` "
            f"and that model `{config.LLM_MODEL}` is available."
        )
        return error_answer, relevant_docs


def build_scan_context(vulnerabilities: List[dict]) -> str:
    """Build a concise scan context string from vulnerability records."""
    if not vulnerabilities:
        return ""
    
    lines = [f"Target scan found {len(vulnerabilities)} findings:"]
    
    # Group by severity
    by_severity = {}
    for v in vulnerabilities:
        sev = v.get("severity", "info")
        by_severity.setdefault(sev, []).append(v)
    
    for sev in ["critical", "high", "medium", "low", "info"]:
        items = by_severity.get(sev, [])
        if items:
            lines.append(f"\n{sev.upper()} ({len(items)}):")
            for v in items[:3]:  # Top 3 per severity
                cve = v.get("cve_id", "")
                name = v.get("name", "")[:60]
                host = v.get("host", "")
                port = v.get("port", "")
                lines.append(f"  - {name} {'('+cve+')' if cve else ''} on {host}:{port}")
    
    return "\n".join(lines)
