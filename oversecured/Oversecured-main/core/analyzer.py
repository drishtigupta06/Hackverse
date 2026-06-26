import os
import yaml
from lxml import etree

class ManifestAnalyzer:
    def __init__(self, rules_dir):
        self.rules_dir = rules_dir
        self.rules = self._load_rules()

    def _load_rules(self):
        rules = []
        if not os.path.exists(self.rules_dir):
            print(f"[-] Warning: Rules directory '{self.rules_dir}' does not exist.")
            return rules
            
        for filename in os.listdir(self.rules_dir):
            if filename.endswith(".yml") or filename.endswith(".yaml"):
                filepath = os.path.join(self.rules_dir, filename)
                with open(filepath, "r") as f:
                    try:
                        data = yaml.safe_load(f)
                        if data and "rules" in data:
                            rules.extend(data["rules"])
                    except Exception as e:
                        print(f"[-] Error loading rule file {filename}: {e}")
        return rules

    def analyze(self, apk_obj):
        findings = []
        try:
            # get_android_manifest_xml() returns an lxml.etree.Element
            manifest_etree = apk_obj.get_android_manifest_xml()
        except Exception as e:
            print(f"[-] Error extracting AndroidManifest.xml: {e}")
            return findings

        if manifest_etree is None:
            print("[-] AndroidManifest.xml could not be parsed.")
            return findings

        # Setup standard Android XML namespace for XPath evaluation
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        
        for rule in self.rules:
            xpath_query = rule.get("xpath")
            if not xpath_query:
                continue
                
            try:
                matches = manifest_etree.xpath(xpath_query, namespaces=ns)
                if matches:
                    finding = {
                        "id": rule.get("id"),
                        "name": rule.get("name"),
                        "description": rule.get("description"),
                        "severity": rule.get("severity", "INFO"),
                        "recommendation": rule.get("recommendation", ""),
                        "type": "manifest",
                        "matches": []
                    }
                    scheme_set = set()
                    host_set = set()
                    path_set = set()
                    for match in matches:
                        tag_name = match.tag
                        name_attr = match.get(f"{{{ns['android']}}}name", "N/A")
                        scheme_attr = match.get(f"{{{ns['android']}}}scheme", "")
                        host_attr = match.get(f"{{{ns['android']}}}host", "")
                        path_attr = match.get(f"{{{ns['android']}}}path", "")
                        if scheme_attr:
                            scheme_set.add(scheme_attr)
                        if host_attr:
                            host_set.add(host_attr)
                        if path_attr:
                            path_set.add(path_attr)
                        # Find parent activity name for context
                        parent = match.getparent()
                        while parent is not None and parent.tag != "activity":
                            parent = parent.getparent()
                        parent_name = parent.get(f"{{{ns['android']}}}name", "") if parent is not None else ""
                        finding["matches"].append(
                            f"<{tag_name} android:name='{name_attr}'"
                            f"{f' android:scheme=''{scheme_attr}''' if scheme_attr else ''}"
                            f"{f' android:host=''{host_attr}''' if host_attr else ''}"
                            f"{f' android:path=''{path_attr}''' if path_attr else ''}"
                            f"{f' parent=''{parent_name}''' if parent_name else ''}>"
                        )

                    if scheme_set:
                        finding["scheme"] = list(scheme_set)[0] if len(scheme_set) == 1 else list(scheme_set)
                    if host_set:
                        finding["host"] = list(host_set)[0] if len(host_set) == 1 else list(host_set)
                    if path_set:
                        finding["deep_link_path"] = list(path_set)[0] if len(path_set) == 1 else list(path_set)
                        
                    findings.append(finding)
            except Exception as e:
                print(f"[-] Error executing XPath for rule {rule.get('id')}: {e}")
                
        return findings
