import frida
import json
import time
import os
from typing import Dict, List, Optional, Any

class FridaManager:
    """
    Enhanced FridaManager for automatic script injection and result collection
    """
    
    def __init__(self, device_id: str = None):
        """
        Initialize Frida manager
        """
        self.device = None
        self.sessions = {}
        self.results = []
        self.scripts = {}
        
        try:
            if device_id:
                self.device = frida.get_device(device_id, timeout=10)
            else:
                self.device = frida.get_usb_device(timeout=10)
            print(f"[+] Connected to device: {self.device}")
        except Exception as e:
            print(f"[-] Failed to connect to device: {e}")
            raise
    
    def inject_script(self, package: str, script_path: str, spawn: bool = True) -> Optional[frida.core.Session]:
        """
        Inject script into target package
        
        Args:
            package: Target package name
            script_path: Path to JS script file
            spawn: Whether to spawn the package or attach to running instance
            
        Returns:
            Frida session object
        """
        if not os.path.exists(script_path):
            print(f"[-] Script file not found: {script_path}")
            return None
            
        try:
            session = None
            
            if spawn:
                print(f"[*] Spawning package: {package}")
                pid = self.device.spawn([package])
                session = self.device.attach(pid)
                self.sessions[package] = session
                
                # Load and inject script
                with open(script_path, 'r', encoding='utf-8') as f:
                    script_code = f.read()
                    
                script = session.create_script(script_code)
                script.on('message', lambda message, data: self.on_message(package, message, data))
                script.load()
                
                print(f"[*] Script loaded, resuming package")
                self.device.resume(pid)
                
            else:
                print(f"[*] Attaching to running package: {package}")
                session = self.device.attach(package)
                self.sessions[package] = session
                
                with open(script_path, 'r', encoding='utf-8') as f:
                    script_code = f.read()
                    
                script = session.create_script(script_code)
                script.on('message', lambda message, data: self.on_message(package, message, data))
                script.load()
            
            self.scripts[package] = script
            print(f"[+] Script injected successfully: {script_path}")
            return session
            
        except Exception as e:
            print(f"[-] Failed to inject script: {e}")
            return None
    
    def on_message(self, package: str, message: Dict, data: bytes = None):
        """
        Handle messages from injected scripts
        
        Args:
            package: Package name
            message: Message from script
            data: Optional binary data
        """
        if message['type'] == 'send':
            payload = message['payload']
            payload['_package'] = package
            payload['_timestamp'] = time.time()
            
            self.results.append(payload)
            
            # Log important events
            event_type = payload.get('type', 'unknown')
            if event_type in ['ssl_bypass', 'root_bypass', 'exploit_found', 'vulnerability']:
                print(f"[+] {package}: {event_type} - {payload.get('status', 'unknown')}")
                
        elif message['type'] == 'error':
            print(f"[-] Script error in {package}: {message['stack']}")
    
    def get_results(self, package: str = None, event_type: str = None) -> List[Dict]:
        """
        Filter and return collected results
        
        Args:
            package: Filter by package name
            event_type: Filter by event type
            
        Returns:
            Filtered results list
        """
        filtered = self.results
        
        if package:
            filtered = [r for r in filtered if r.get('_package') == package]
            
        if event_type:
            filtered = [r for r in filtered if r.get('type') == event_type]
            
        return filtered
    
    def detach_all(self):
        """Detach from all sessions"""
        for package, session in self.sessions.items():
            try:
                session.detach()
                print(f"[+] Detached from {package}")
            except Exception as e:
                print(f"[-] Error detaching from {package}: {e}")
        
        self.sessions.clear()
        self.scripts.clear()
    
    def spawn_and_hook(self, package: str, scripts_dir: str) -> bool:
        """
        Spawn package and inject all scripts from directory
        
        Args:
            package: Target package name
            scripts_dir: Directory containing JS scripts
            
        Returns:
            Success status
        """
        if not os.path.exists(scripts_dir):
            print(f"[-] Scripts directory not found: {scripts_dir}")
            return False
            
        try:
            # Spawn the package
            print(f"[*] Spawning package: {package}")
            pid = self.device.spawn([package])
            session = self.device.attach(pid)
            self.sessions[package] = session
            
            # Inject all scripts
            script_files = [f for f in os.listdir(scripts_dir) if f.endswith('.js')]
            
            for script_file in script_files:
                script_path = os.path.join(scripts_dir, script_file)
                
                with open(script_path, 'r', encoding='utf-8') as f:
                    script_code = f.read()
                    
                script = session.create_script(script_code)
                script.on('message', lambda message, data: self.on_message(package, message, data))
                script.load()
                
                print(f"[+] Loaded script: {script_file}")
            
            # Resume the package
            self.device.resume(pid)
            print(f"[+] Package spawned and hooked with {len(script_files)} scripts")
            return True
            
        except Exception as e:
            print(f"[-] Failed to spawn and hook: {e}")
            return False
    
    def list_applications(self) -> List[Dict]:
        """List installed applications"""
        try:
            applications = self.device.enumerate_applications()
            return [{ 'name': app.name, 'pid': app.pid, 'identifier': app.identifier } for app in applications]
        except Exception as e:
            print(f"[-] Failed to list applications: {e}")
            return []
    
    def kill_package(self, package: str) -> bool:
        """Kill target package"""
        try:
            self.device.kill(package)
            print(f"[+] Killed package: {package}")
            return True
        except Exception as e:
            print(f"[-] Failed to kill {package}: {e}")
            return False

# Enhanced FridaIntegration for manifest scanner
class FridaIntegration:
    """
    Integration layer for manifest scanner
    """
    
    def __init__(self, device_id: str = None):
        self.manager = FridaManager(device_id)
        self.frida_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frida_scripts')
        
    def run_full_analysis(self, package: str, timeout: int = 30) -> Dict:
        """
        Run complete Frida analysis on package
        
        Args:
            package: Target package name
            timeout: Analysis timeout in seconds
            
        Returns:
            Analysis results dictionary
        """
        print(f"[*] Starting full Frida analysis on {package}")
        
        # Step 1: Spawn and inject all scripts
        success = self.manager.spawn_and_hook(package, self.frida_dir)
        
        if not success:
            return {'status': 'failed', 'error': 'Failed to spawn and hook'}
        
        # Step 2: Wait for results
        print(f"[*] Waiting {timeout} seconds for analysis results...")
        time.sleep(timeout)
        
        # Step 3: Collect all results
        results = {
            'status': 'completed',
            'package': package,
            'findings': self.manager.results,
            'summary': self._generate_summary()
        }
        
        # Step 4: Cleanup
        self.manager.detach_all()
        
        return results
    
    def _generate_summary(self) -> Dict:
        """Generate analysis summary from collected results"""
        summary = {
            'total_events': len(self.manager.results),
            'ssl_bypass': len([r for r in self.manager.results if r.get('type') == 'ssl_bypass']),
            'root_bypass': len([r for r in self.manager.results if r.get('type') == 'root_bypass']),
            'exploits': len([r for r in self.manager.results if r.get('type') == 'exploit_found']),
            'secrets': len([r for r in self.manager.results if r.get('type') == 'secret_found']),
            'network': len([r for r in self.manager.results if r.get('type') == 'network_call'])
        }
        
        return summary

