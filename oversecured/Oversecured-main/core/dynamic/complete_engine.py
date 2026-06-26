#!/usr/bin/env python3
"""
Complete Dynamic Analysis Engine Integration
Combines UIAutomator2, WebView exploitation, and scanner integration
"""

import os
import sys
import time
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import logging

from .ui_exploiter import UIExploiter, UIFinding
from .webview_exploiter import WebViewExploiter, WebViewFinding
from ..frida.frida_enhanced import EnhancedFridaAnalyzer

logger = logging.getLogger(__name__)

@dataclass
class DynamicAnalysisResult:
    """Complete dynamic analysis result"""
    package: str
    start_time: str
    end_time: str
    total_findings: int
    ui_findings: List[UIFinding]
    webview_findings: List[WebViewFinding]
    frida_findings: List[Dict]
    confidence_score: float
    exploit_paths: List[Dict]
    screenshots_taken: int
    status: str

class CompleteDynamicEngine:
    """
    Complete dynamic analysis engine combining all exploration techniques
    """
    
    def __init__(self, package: str, apk_path: str = None, output_dir: str = "dynamic_reports"):
        self.package = package
        self.apk_path = apk_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize components
        self.ui_exploiter = UIExploiter(package, str(self.output_dir / "ui_results"))
        self.webview_exploiter = WebViewExploiter(package, str(self.output_dir / "webview_results"))
        
        # Frida integration (optional)
        self.frida_analyzer = None
        try:
            self.frida_analyzer = EnhancedFridaAnalyzer()
        except Exception as e:
            logger.warning(f"Frida not available: {e}")
        
        # Results
        self.ui_findings = []
        self.webview_findings = []
        self.frida_findings = []
        
    def run_complete_analysis(self, max_screens: int = 20, max_time: int = 300, use_frida: bool = False) -> DynamicAnalysisResult:
        """
        Run complete dynamic analysis combining all techniques
        
        Args:
            max_screens: Maximum screens to explore
            max_time: Maximum time in seconds
            use_frida: Whether to use Frida analysis
            
        Returns:
            Complete analysis result
        """
        start_time = time.ctime()
        logger.info(f"Starting complete dynamic analysis for {self.package}")
        
        try:
            # Phase 1: UIAutomator2 exploitation
            logger.info("Phase 1: UIAutomator2 exploitation")
            ui_results = self.ui_exploiter.start_exploitation(max_screens, max_time // 2)
            self.ui_findings = self.ui_exploiter.findings
            
            logger.info(f"UI exploration completed: {len(self.ui_findings)} findings")
            
            # Phase 2: WebView analysis
            logger.info("Phase 2: WebView analysis")
            webview_results = self.webview_exploiter.analyze_webviews()
            self.webview_findings = self.webview_exploiter.findings
            
            logger.info(f"WebView analysis completed: {len(self.webview_findings)} findings")
            
            # Phase 3: Frida analysis (if available)
            if use_frida and self.frida_analyzer:
                logger.info("Phase 3: Frida analysis")
                frida_results = self.frida_analyzer.run_full_analysis(self.package, timeout=max_time // 2)
                self.frida_findings = frida_results.get('results', [])
                
                logger.info(f"Frida analysis completed: {len(self.frida_findings)} findings")
            
            # Generate exploit paths
            exploit_paths = self.generate_exploit_paths()
            
            # Calculate confidence score
            confidence_score = self.calculate_confidence_score()
            
            # Create result
            end_time = time.ctime()
            
            result = DynamicAnalysisResult(
                package=self.package,
                start_time=start_time,
                end_time=end_time,
                total_findings=len(self.ui_findings) + len(self.webview_findings) + len(self.frida_findings),
                ui_findings=self.ui_findings,
                webview_findings=self.webview_findings,
                frida_findings=self.frida_findings,
                confidence_score=confidence_score,
                exploit_paths=exploit_paths,
                screenshots_taken=self.count_screenshots(),
                status="completed"
            )
            
            # Save complete report
            self.save_complete_report(result)
            
            logger.info(f"Complete dynamic analysis finished: {result.total_findings} total findings")
            return result
            
        except Exception as e:
            logger.error(f"Complete analysis failed: {e}")
            
            # Return partial result
            return DynamicAnalysisResult(
                package=self.package,
                start_time=start_time,
                end_time=time.ctime(),
                total_findings=len(self.ui_findings) + len(self.webview_findings) + len(self.frida_findings),
                ui_findings=self.ui_findings,
                webview_findings=self.webview_findings,
                frida_findings=self.frida_findings,
                confidence_score=0.0,
                exploit_paths=[],
                screenshots_taken=self.count_screenshots(),
                status="failed"
            )
    
    def generate_exploit_paths(self) -> List[Dict]:
        """
        Generate exploit paths from combined findings
        """
        exploit_paths = []
        
        try:
            # Find UI + WebView combinations
            ui_crash_findings = [f for f in self.ui_findings if f.type == "crash_on_input"]
            webview_interface_findings = [f for f in self.webview_findings if f.type == "javascript_interface_exposed"]
            
            for ui_finding in ui_crash_findings:
                for webview_finding in webview_interface_findings:
                    if ui_finding.activity == webview_finding.activity:
                        exploit_paths.append({
                            "type": "ui_crash_to_webview_interface",
                            "description": "Crash input field leading to exposed JS interface",
                            "steps": [
                                f"Navigate to {ui_finding.activity}",
                                f"Input crash payload: {ui_finding.payload}",
                                "Trigger crash in WebView",
                                f"Access JS interface: {webview_finding.js_interface_name}",
                                "Execute arbitrary JavaScript"
                            ],
                            "confidence": 0.8,
                            "severity": "critical"
                        })
            
            # Find SQL injection + path traversal combinations
            sql_findings = [f for f in self.ui_findings if f.type == "sql_injection"]
            path_findings = [f for f in self.ui_findings if f.type == "path_traversal"]
            
            for sql_finding in sql_findings[:3]:  # Limit to prevent excessive paths
                for path_finding in path_findings[:3]:
                    if sql_finding.activity == path_finding.activity:
                        exploit_paths.append({
                            "type": "sql_to_path_traversal",
                            "description": "SQL injection leading to path traversal",
                            "steps": [
                                f"Navigate to {sql_finding.activity}",
                                f"Inject SQL payload: {sql_finding.payload}",
                                "Extract database information",
                                f"Use path traversal: {path_finding.payload}",
                                "Access sensitive files"
                            ],
                            "confidence": 0.7,
                            "severity": "high"
                        })
            
            # Find XSS + file access combinations
            xss_findings = [f for f in self.ui_findings if f.type == "cross_site_scripting"]
            file_access_findings = [f for f in self.webview_findings if f.type == "file_access_vulnerability"]
            
            for xss_finding in xss_findings[:3]:
                for file_finding in file_access_findings[:3]:
                    if xss_finding.activity == file_finding.activity:
                        exploit_paths.append({
                            "type": "xss_to_file_access",
                            "description": "XSS leading to file system access",
                            "steps": [
                                f"Navigate to {xss_finding.activity}",
                                f"Inject XSS payload: {xss_finding.payload}",
                                "Execute JavaScript in WebView",
                                f"Access local files: {file_finding.poc_payload}",
                                "Exfiltrate sensitive data"
                            ],
                            "confidence": 0.9,
                            "severity": "critical"
                        })
            
        except Exception as e:
            logger.error(f"Exploit path generation failed: {e}")
        
        return exploit_paths
    
    def calculate_confidence_score(self) -> float:
        """
        Calculate overall confidence score for dynamic analysis
        """
        try:
            total_findings = len(self.ui_findings) + len(self.webview_findings) + len(self.frida_findings)
            
            if total_findings == 0:
                return 0.0
            
            # Weight findings by severity
            high_weight = 0.3
            medium_weight = 0.1
            low_weight = 0.05
            
            score = 0.0
            
            # UI findings
            for finding in self.ui_findings:
                if finding.severity == "high":
                    score += high_weight * finding.confidence
                elif finding.severity == "medium":
                    score += medium_weight * finding.confidence
                else:
                    score += low_weight * finding.confidence
            
            # WebView findings
            for finding in self.webview_findings:
                if finding.severity == "high":
                    score += high_weight * finding.confidence
                elif finding.severity == "medium":
                    score += medium_weight * finding.confidence
                else:
                    score += low_weight * finding.confidence
            
            # Frida findings (if available)
            for finding in self.frida_findings:
                confidence = finding.get('confidence', 0.5)
                severity = finding.get('severity', 'medium')
                
                if severity == "high":
                    score += high_weight * confidence
                elif severity == "medium":
                    score += medium_weight * confidence
                else:
                    score += low_weight * confidence
            
            # Normalize to 0-1 range
            max_possible_score = total_findings * high_weight
            if max_possible_score > 0:
                score = min(score / max_possible_score, 1.0)
            
            return score
            
        except Exception as e:
            logger.error(f"Confidence calculation failed: {e}")
            return 0.0
    
    def count_screenshots(self) -> int:
        """Count total screenshots taken"""
        try:
            screenshot_count = 0
            
            # Count UI screenshots
            ui_screenshots = list(Path(self.ui_exploiter.output_dir).glob("*.png"))
            screenshot_count += len(ui_screenshots)
            
            # Count WebView screenshots
            webview_screenshots = list(Path(self.webview_exploiter.output_dir).glob("*.png"))
            screenshot_count += len(webview_screenshots)
            
            return screenshot_count
            
        except Exception as e:
            logger.error(f"Screenshot counting failed: {e}")
            return 0
    
    def save_complete_report(self, result: DynamicAnalysisResult):
        """
        Save complete dynamic analysis report
        """
        try:
            # Prepare report data
            report_data = {
                'package': result.package,
                'analysis_info': {
                    'start_time': result.start_time,
                    'end_time': result.end_time,
                    'status': result.status
                },
                'summary': {
                    'total_findings': result.total_findings,
                    'ui_findings': len(result.ui_findings),
                    'webview_findings': len(result.webview_findings),
                    'frida_findings': len(result.frida_findings),
                    'confidence_score': result.confidence_score,
                    'exploit_paths': len(result.exploit_paths),
                    'screenshots_taken': result.screenshots_taken
                },
                'findings_by_type': {
                    'ui_exploitation': [asdict(f) for f in result.ui_findings],
                    'webview_vulnerabilities': [asdict(f) for f in result.webview_findings],
                    'frida_analysis': result.frida_findings
                },
                'exploit_paths': result.exploit_paths,
                'detailed_findings': {
                    'ui_findings': [asdict(f) for f in result.ui_findings],
                    'webview_findings': [asdict(f) for f in result.webview_findings],
                    'frida_findings': result.frida_findings
                }
            }
            
            # Save comprehensive report
            report_path = self.output_dir / f"{result.package}_dynamic_analysis.json"
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            logger.info(f"Complete dynamic analysis report saved to {report_path}")
            
            # Save exploit paths separately
            if result.exploit_paths:
                paths_path = self.output_dir / f"{result.package}_exploit_paths.json"
                with open(paths_path, 'w') as f:
                    json.dump(result.exploit_paths, f, indent=2)
                
                logger.info(f"Exploit paths saved to {paths_path}")
            
        except Exception as e:
            logger.error(f"Report saving failed: {e}")
    
    def get_high_confidence_findings(self, min_confidence: float = 0.7) -> List[Dict]:
        """
        Get high confidence findings
        """
        try:
            high_confidence = []
            
            # UI findings
            for finding in self.ui_findings:
                if finding.confidence >= min_confidence:
                    high_confidence.append({
                        'type': 'ui',
                        'finding': asdict(finding)
                    })
            
            # WebView findings
            for finding in self.webview_findings:
                if finding.confidence >= min_confidence:
                    high_confidence.append({
                        'type': 'webview',
                        'finding': asdict(finding)
                    })
            
            # Frida findings
            for finding in self.frida_findings:
                confidence = finding.get('confidence', 0.0)
                if confidence >= min_confidence:
                    high_confidence.append({
                        'type': 'frida',
                        'finding': finding
                    })
            
            return high_confidence
            
        except Exception as e:
            logger.error(f"High confidence filtering failed: {e}")
            return []

# Integration with scanner.py
def run_dynamic_analysis(args) -> Dict:
    """
    Integration point for scanner.py
    """
    try:
        # Create dynamic engine
        engine = CompleteDynamicEngine(
            package=args.dynamic_pkg or args.package,
            apk_path=args.apk,
            output_dir="dynamic_analysis"
        )
        
        # Run complete analysis
        result = engine.run_complete_analysis(
            max_screens=args.dynamic_max_screens,
            max_time=300,  # 5 minutes max
            use_frida=True
        )
        
        # Convert to scanner format
        dynamic_results = {
            'summary': {
                'screens_explored': result.screens_taken,
                'ui_findings': len(result.ui_findings),
                'webview_findings': len(result.webview_findings),
                'frida_findings': len(result.frida_findings),
                'total_findings': result.total_findings,
                'confidence_score': result.confidence_score,
                'exploit_paths': len(result.exploit_paths)
            },
            'dynamic_findings': [asdict(finding) for finding in result.ui_findings],
            'webview_findings': [asdict(finding) for finding in result.webview_findings],
            'frida_findings': result.frida_findings,
            'exploit_paths': result.exploit_paths,
            'status': result.status
        }
        
        return dynamic_results
        
    except Exception as e:
        logger.error(f"Dynamic analysis integration failed: {e}")
        return {'status': 'failed', 'error': str(e)}


