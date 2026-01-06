import json
import subprocess
import time
import pandas as pd
from pathlib import Path

from testers.base_tester import BaseTester
from testers.utils import Finding

class SemgrepTester(BaseTester):
    """Semgrep implementation"""
    
    def __init__(self):
        super().__init__("Semgrep")
        self.semgrep_cwe_mapping = self.load_semgrep_cwe_mapping()
    
    def load_semgrep_cwe_mapping(self) -> dict[str, str]:
        csv_path = Path(__file__).parent.parent.parent / 'Real_world_vulnerability_dataset' / 'CWE_mapping' / 'Semgrep_CWE-1000.csv'
        
        if not Path(csv_path).exists():
            print(f"Warning: {csv_path} not found")
            return {}
        
        df = pd.read_csv(csv_path)
        mapping = {}
        
        for _, row in df.iterrows():
            rule_id = row['rule']
            cwe_class = row['cwe-1000']
            
            if pd.notna(cwe_class):
                classes = str(cwe_class).split(',')
                first_class = classes[0].strip()
                if first_class.isdigit():
                    mapping[rule_id] = f"CWE-{first_class}"
        
        print(f"Loaded {len(mapping)} Semgrep rule mappings")
        return mapping
    
    def get_cwe_class_from_rule(self, rule_id: str) -> str:
        return self.semgrep_cwe_mapping.get(rule_id)

    def run_scan(self, code_dir: Path) -> tuple[list[Finding], float]:
        """Run Semgrep on directory"""
        start_time = time.time()

        try:
            cmd = ["semgrep", "--config=p/java", "--json", str(code_dir)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            scan_time = time.time() - start_time

            if result.returncode != 0 and not result.stdout:
                return [], scan_time

            output = json.loads(result.stdout)
            findings = self.parse_output(output, code_dir)
            return findings, scan_time

        except subprocess.TimeoutExpired:
            return [], 60.0
        except Exception as e:
            print(f"Semgrep error: {e}")
            return [], time.time() - start_time

    def parse_output(self, output: dict, code_dir: Path) -> list[Finding]:
        """Parse Semgrep JSON to Finding objects"""
        findings = []

        for result in output.get('results', []):
            metadata = result.get('extra', {}).get('metadata', {})
            cwe_list = metadata.get('cwe', [])
            
            cwe_id = None
            if cwe_list:
                cwe_str = cwe_list[0]
                if ':' in cwe_str:
                    cwe_id = cwe_str.split(':')[0].strip()
                else:
                    cwe_id = cwe_str.strip()

            abs_path = Path(result.get('path', ''))
            try:
                rel_path = abs_path.relative_to(code_dir)
            except ValueError:
                rel_path = abs_path

            finding = Finding(
                file_path=str(rel_path),
                line_number=result.get('start', {}).get('line', 0),
                end_line=result.get('end', {}).get('line'),
                rule_id=result.get('check_id', ''),
                cwe_id=cwe_id,
                message=result.get('extra', {}).get('message', ''),
                severity=metadata.get('severity', 'WARNING')
            )
            findings.append(finding)

        return findings
