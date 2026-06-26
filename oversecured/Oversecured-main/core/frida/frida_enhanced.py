#!/usr/bin/env python3
"""
Enhanced Frida Analyzer for Manifest Scanner
Integrates with enhanced scripts and provides comprehensive dynamic analysis
"""

import json
import os
import sys
import subprocess
import threading
import time
from typing import Dict, List, Optional, Any

from .frida_manager import FridaManager, FridaIntegration

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

class EnhancedFridaAnalyzer:
    """
    Enhanced Frida analyzer with improved script management
    """
    
    def __init__(self, device_id: str = None, timeout: int = 30):
        self.device_id = device_id
        self.timeout = timeout
        self.integration = None
        self.results = []
        self.frida_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'frida_scripts')
        
        # Enhanced script paths
        self.scripts = {
            'ssl_bypass': os.path.join(self.frida_dir, 'enhanced_ssl_bypass.js'),
            'root_bypass': os.path.join(self.frida_dir, 'enhanced_root_bypass.js'),
            'webview': os.path.join(self.frida_dir, 'webview_monitor.js'),
            'api': os.path.join(self.frida_dir, 'api_monitor.js'),
            'prefs': os.path.join(self.frida_dir, 'sharedprefs_monitor.js'),
            'file': os.path.join(self.frida_dir, 'file_monitor.js'),
            'secrets': os.path.join(self.frida_dir, 'secrets_monitor.js'),
            'intent': os.path.join(self.frida_dir, 'intent_monitor.js')
        }
        
    def check_frida_availability(self) -> bool:
        """Check if Frida is available and connected"""
        if not FRIDA_AVAILABLE:
            print("[-] Frida not installed. Install with: pip install frida-tools")
            return False
            
        try:
            if self.device_id:
                device = frida.get_device(self.device_id, timeout=10)
            else:
                device = frida.get_usb_device(timeout=10)
            
            # Test connection by listing processes
            processes = device.enumerate_processes()
            print(f"[+] Frida connected to device with {len(processes)} processes")
            return True
            
        except Exception as e:
            print(f"[-] Frida connection failed: {e}")
            return False
    
    def analyze_package(self, package_name: str, modules: List[str] = None) -> Dict:
        """
        Analyze package with specified modules
        
        Args:
            package_name: Target package name
            modules: List of modules to run (default: all)
            
        Returns:
            Analysis results dictionary
        """
        if not modules:
            modules = ['ssl_bypass', 'root_bypass', 'webview', 'api', 'prefs', 'file', 'secrets', 'intent']
        
        print(f"[*] Starting Frida analysis on {package_name}")
        print(f"[*] Modules: {', '.join(modules)}")
        
        try:
            # Initialize integration
            self.integration = FridaIntegration(self.device_id)
            
            # Step 1: Spawn package and inject scripts
            print(f"[*] Spawning {package_name} and injecting scripts...")
            
            sessions = {}
            session = self.integration.manager.spawn(package_name)
            
            # Inject requested modules
            for module in modules:
                script_path = self.scripts.get(module)
                if script_path and os.path.exists(script_path):
                    print(f"[*] Injecting {module}...")
                    
                    with open(script_path, 'r', encoding='utf-8') as f:
                        script_code = f.read()
                        
                    script = session.create_script(script_code)
                    script.on('message', lambda message, data: self._on_message(module, message, data))
                    script.load()
                    
                else:
                    print(f"[-] Script not found: {module}")
            
            # Resume the package
            self.integration.manager.device.resume(session.pid)
            
            print(f"[*] Analysis running, waiting {self.timeout} seconds...")
            time.sleep(self.timeout)
            
            # Collect results
            results = self._collect_results(package_name, modules)
            
            # Cleanup
            session.detach()
            
            return results
            
        except Exception as e:
            print(f"[-] Analysis failed: {e}")
            return {'status': 'failed', 'error': str(e)}
    
    def _on_message(self, module: str, message: Dict, data: bytes = None):
        """Handle messages from Frida scripts"""
        if message['type'] == 'send':
            payload = message['payload']
            payload['_module'] = module
            payload['_timestamp'] = time.time()
            
            self.results.append(payload)
            
            # Log important events
            event_type = payload.get('type', 'unknown')
            if event_type in ['ssl_bypass', 'root_bypass', 'exploit_found', 'vulnerability']:
                print(f"[+] {module}: {event_type} - {payload.get('status', 'unknown')}")
                
        elif message['type'] == 'error':
            print(f"[-] Script error in {module}: {message['stack']}")
    
    def _collect_results(self, package: str, modules: List[str]) -> Dict:
        """Collect and format analysis results"""
        
        # Group results by module
        module_results = {}
        for module in modules:
            module_results[module] = [r for r in self.results if r.get('_module') == module]
        
        # Calculate summary
        summary = {
            'package': package,
            'modules_analyzed': modules,
            'total_events': len(self.results),
            'ssl_bypass_count': len([r for r in self.results if r.get('type') == 'ssl_bypass']),
            'root_bypass_count': len([r for r in self.results if r.get('type') == 'root_bypass']),
            'exploit_count': len([r for r in self.results if r.get('type') == 'exploit_found']),
            'secret_count': len([r for r in self.results if r.get('type') == 'secret_found']),
            'api_call_count': len([r for r in self.results if r.get('type') == 'api_call']),
            'file_access_count': len([r for r in self.results if r.get('type') == 'file_access']),
            'intent_count': len([r for r in self.results if r.get('type') == 'intent_received']),
            
            # Module-specific summaries
            'by_module': {module: len(module_results.get(module, [])) for module in modules}
        }
        
        return {
            'status': 'completed',
            'package': package,
            'summary': summary,
            'results': self.results,
            'module_results': module_results
        }
    
    def run_ssl_pinning_detection(self, package: str) -> Dict:
        """Run only SSL pinning detection"""
        return self.analyze_package(package, ['ssl_bypass'])
    
    def run_root_detection_bypass(self, package: str) -> Dict:
        """Run only root detection bypass"""
        return self.analyze_package(package, ['root_bypass'])
    
    def run_webview_analysis(self, package: str) -> Dict:
        """Run only WebView analysis"""
        return self.analyze_package(package, ['webview'])
    
    def run_full_analysis(self, package: str) -> Dict:
        """Run complete analysis with all modules"""
        return self.analyze_package(package)
    
    def get_available_scripts(self) -> Dict:
        """Get list of available scripts"""
        available = {}
        for name, path in self.scripts.items():
            available[name] = {
                'path': path,
                'exists': os.path.exists(path),
                'size': os.path.getsize(path) if os.path.exists(path) else 0
            }
        return available

# Enhanced version for scanner.py integration
def check_frida_availability():
    """Global function to check Frida availability"""
    analyzer = EnhancedFridaAnalyzer()
    return analyzer.check_frida_availability()

