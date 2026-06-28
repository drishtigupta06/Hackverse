import logging
import requests
from bs4 import BeautifulSoup
from typing import List, Dict, Any
from datetime import datetime
import re

logger = logging.getLogger(__name__)

def get_latest_threat_intel() -> List[Dict[str, Any]]:
    """
    Scrapes the latest security news from The Hacker News.
    """
    url = "https://thehackernews.com/"
    intel_data = []
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find all article posts
        articles = soup.find_all('div', class_='body-post')
        
        for article in articles:
            # Extract title
            title_tag = article.find('h2', class_='home-title')
            title = title_tag.text.strip() if title_tag else "No Title"
            
            # Extract description
            desc_tag = article.find('div', class_='home-desc')
            description = desc_tag.text.strip() if desc_tag else "No Description"
            
            # Extract date
            date_tag = article.find('span', class_='h-datetime')
            published_date = ""
            if date_tag:
                # Remove clock icon/text if present
                published_date_str = date_tag.text.strip().replace('', '')
                try:
                    # Try to parse or just keep as string
                    published_date = published_date_str
                except:
                    published_date = datetime.utcnow().isoformat()
            else:
                published_date = datetime.utcnow().isoformat()

            # Attempt to find CVE ID in title or description
            cve_match = re.search(r'CVE-\d{4}-\d{4,7}', title + " " + description, re.IGNORECASE)
            cve_id = cve_match.group(0).upper() if cve_match else None
            
            # Severity based on keywords (heuristic)
            severity = "medium"
            if any(k in (title + description).lower() for k in ["critical", "zero-day", "rce", "backdoor", "unauthenticated"]):
                severity = "critical"
            elif any(k in (title + description).lower() for k in ["high", "exploit", "broken", "flaw"]):
                severity = "high"
            
            # CVSS score (simulated if not found)
            cvss_score = 9.8 if severity == "critical" else 7.5 if severity == "high" else 5.0
            
            intel_data.append({
                "cve_id": cve_id,
                "title": title,
                "description": description,
                "severity": severity,
                "cvss_score": cvss_score,
                "published_date": published_date,
                "source": "The Hacker News",
                "mitre_tactic": "Initial Access" if severity == "critical" else "Execution",
                "mitre_technique": "T1190 Exploit Public-Facing Application"
            })
            
            if len(intel_data) >= 10:
                break
                
    except Exception as e:
        logger.error(f"Failed to scrape threat intel: {e}")
        # Fallback to some static data if scraping fails completely
        return [
            {
                "cve_id": "CVE-2024-3094",
                "title": "XZ Utils Backdoor (Fallback)",
                "description": "Critical backdoor found in XZ Utils. This is a fallback entry because the live scraper encountered an issue.",
                "severity": "critical",
                "cvss_score": 10.0,
                "published_date": datetime.utcnow().isoformat(),
                "source": "CyberGuard Fallback",
                "mitre_tactic": "Execution",
                "mitre_technique": "T1059"
            }
        ]
        
    return intel_data
