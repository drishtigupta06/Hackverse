import json
import logging
from typing import List, Dict, Any
from openai import OpenAI
import config

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are CyberGuard's Advanced Threat Modeling Engine.
Your task is to take a list of vulnerabilities and open ports discovered on a target host
and simulate a realistic, step-by-step attack chain that an adversary might use to fully compromise the system.

Output your response STRICTLY as a JSON array of objects. Do not include markdown codeblocks, just the raw JSON.
Each object in the array MUST have the following keys:
- "step": integer (starting at 1)
- "title": string (e.g., "Initial Reconnaissance", "Exploit Apache Struts", "Dump Credentials")
- "description": string (Detailed explanation of what the attacker does in this step, referencing the specific vulnerabilities if applicable)
- "technique": string (MITRE ATT&CK technique ID and name, e.g., "T1190 Exploit Public-Facing Application")
"""

def generate_attack_chain(scan_id: str, target: str, vulnerabilities: List[Dict[str, Any]], ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Uses the configured LLM to generate a simulated attack chain based on scan findings.
    """
    client = OpenAI(
        base_url=config.LLM_BASE_URL,
        api_key=config.LLM_API_KEY,
    )

    context = f"Target: {target}\n\nOpen Ports & Services:\n"
    if not ports:
        context += "- No open ports identified.\n"
    else:
        for p in ports:
            context += f"- Port {p.get('port')}/{p.get('protocol')} ({p.get('service')} {p.get('version')})\n"
    
    context += "\nVulnerabilities Discovered:\n"
    if not vulnerabilities:
        context += "- No specific vulnerabilities identified.\n"
    else:
        for v in vulnerabilities:
            severity = v.get('severity', 'info').upper()
            context += f"- [{severity}] {v.get('cve_id') or 'Finding'}: {v.get('name')}\n  Details: {v.get('description', '')[:200]}\n"
        
    user_prompt = f"Analyze the following scan results and generate a step-by-step attack simulation chain.\n\n{context}"

    try:
        response = client.chat.completions.create(
            model=config.LLM_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2, # Low temp for structured output
        )
        content = response.choices[0].message.content.strip()
        
        # Strip markdown code blocks if the LLM hallucinated them despite the prompt
        if content.startswith("```json"):
            content = content.split("```json")[-1]
        if content.startswith("```"):
            content = content.split("```")[-1]
        if content.endswith("```"):
            content = content.rsplit("```", 1)[0]
            
        content = content.strip()

        attack_chain = json.loads(content)
        return attack_chain
        
    except json.JSONDecodeError as je:
        logger.error(f"[simulator] Failed to parse JSON from LLM: {content}")
        return [{
            "step": 1, 
            "title": "Simulation Generation Error", 
            "description": "The AI Engine failed to format the attack chain as valid JSON. It might be due to a timeout or a long reasoning context.", 
            "technique": "T1498 Network Denial of Service (Internal)"
        }]
    except Exception as e:
        logger.error(f"[simulator] LLM call failed: {e}")
        return [{
            "step": 1, 
            "title": "Engine Unavailable", 
            "description": f"Failed to connect to the AI engine ({config.LLM_BASE_URL}). Check if the Ollama/OpenAI service is running.", 
            "technique": "Offline"
        }]
