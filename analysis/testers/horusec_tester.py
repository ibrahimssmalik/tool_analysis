import json
import subprocess
import tempfile
import time
from pathlib import Path

from testers.utils import Finding, CVETestResult
from testers.utils import CVEInfo, MethodInfo

class HorusecTester:
    def __init__(self):
        self.tool_name = "Horusec"
        self.horusec_cwe_mapping = self.load_horusec_cwe_mapping()
    
    def load_horusec_cwe_mapping(self) -> dict[str, str]:
        """Load Horusec rule -> CWE class mapping"""
        csv_path = '../Real_world_vulnerability_dataset/CWE_mapping/Horusec_cwe.csv'
        
        if not Path(csv_path).exists():
            print(f"Warning: {csv_path} not found")
            return {}
        
        import pandas as pd
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
        
        print(f"Loaded {len(mapping)} Horusec rule mappings")
        return mapping
    
    def get_cwe_class_from_rule(self, rule_id: str) -> str:
        """Get CWE class from Horusec rule ID"""
        return self.horusec_cwe_mapping.get(rule_id)

    def create_temp_file(self, method: MethodInfo, temp_dir: Path) -> Path:
        """Create temporary Java file from method info"""
        file_path = temp_dir / method.file_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(method.source_code)
        
        return file_path

    def run_horusec(self, code_dir: Path) -> tuple[list[Finding], float]:
        """Run Horusec on code directory"""
        start_time = time.time()

        try:
            # Create output file in temp location
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                output_file = Path(tmp.name)
            
            cmd = [
                "horusec", "start",
                "-p", str(code_dir),
                "-D",
                "-o", "json",
                "-O", str(output_file)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            scan_time = time.time() - start_time

            # Check if Horusec succeeded
            if result.returncode != 0:
                stderr = result.stderr[:200] if result.stderr else "No error output"
                print(f"    Horusec exited with code {result.returncode}: {stderr}")
                return [], scan_time

            # Read output file
            if output_file.exists():
                with open(output_file) as f:
                    try:
                        output = json.load(f)
                    except json.JSONDecodeError as e:
                        print(f"    Horusec JSON parse error: {e}")
                        return [], scan_time
                
                output_file.unlink()
                
                # Check status
                status = output.get('status')
                if status == 'error':
                    errors = output.get('errors', 'Unknown error')
                    print(f"    Horusec error: {errors}")
                    return [], scan_time
                
                findings = self.parse_horusec_output(output, code_dir)
                return findings, scan_time
            else:
                print(f"    Horusec output file not created")
                return [], scan_time

        except subprocess.TimeoutExpired:
            print(f"    Horusec timeout after 120s")
            return [], 120.0
        except FileNotFoundError:
            print(f"    Horusec not found - is it installed?")
            print(f"    Install: https://docs.horusec.io/docs/cli/installation/")
            return [], 0.0
        except Exception as e:
            print(f"    Horusec unexpected error: {e}")
            return [], time.time() - start_time
        finally:
            # Clean up temp file if it exists
            if 'output_file' in locals() and output_file.exists():
                try:
                    output_file.unlink()
                except:
                    pass

    def parse_horusec_output(self, output: dict, code_dir: Path) -> list[Finding]:
        """Parse Horusec JSON output to Finding objects"""
        findings = []

        analysis_vulns = output.get('analysisVulnerabilities')
        if not analysis_vulns: # Handles None, [], or missing key
            return []
        
        for analysis_vuln in analysis_vulns:
            vuln = analysis_vuln.get('vulnerabilities', {})
            if not vuln: # Skip if vulnerabilities is None or empty
                continue
            
            # Extract file path
            file = vuln.get('file', '')
            
            # Extract line number
            line_str = vuln.get('line', '0')
            try:
                line_number = int(line_str)
            except ValueError:
                line_number = 0
            
            # Extract rule ID
            rule_id = vuln.get('rule_id', '')
            
            # Horusec doesn't include CWE in output, it's in mapping
            cwe_id = None # We'll use rule mapping instead
            
            finding = Finding(
                file_path=file,
                line_number=line_number,
                end_line=None, # Horusec doesn't provide end line
                rule_id=rule_id,
                cwe_id=cwe_id,
                message=vuln.get('details', ''),
                severity=vuln.get('severity', 'UNKNOWN')
            )
            findings.append(finding)

        return findings

    def test_cve(self, cve_info: CVEInfo, expected_cwe: str = None) -> CVETestResult:
        """Test a single CVE with vulnerable and patched versions"""
        print(f"  Testing {cve_info.cve_id} ({cve_info.project_name})...")

        with tempfile.TemporaryDirectory() as temp_vul, \
             tempfile.TemporaryDirectory() as temp_patch:

            temp_vul_path = Path(temp_vul)
            temp_patch_path = Path(temp_patch)

            # Create vulnerable version files
            for method in cve_info.vulnerable_methods:
                self.create_temp_file(method, temp_vul_path)

            # Scan vulnerable version
            vul_findings, vul_time = self.run_horusec(temp_vul_path)

            # Create and scan patched version
            patch_findings = []
            patch_time = 0.0
            if cve_info.patched_methods:
                for method in cve_info.patched_methods:
                    self.create_temp_file(method, temp_patch_path)
                patch_findings, patch_time = self.run_horusec(temp_patch_path)

            # Evaluate detection
            result = self.evaluate_detection(
                cve_info, vul_findings, patch_findings, expected_cwe, vul_time, patch_time
            )
            return result

    @staticmethod
    def cwe_tp(tool_cwe_class: str, expected_cwe_class: str) -> bool:
        """Check if tool's CWE class matches expected"""
        if not tool_cwe_class or not expected_cwe_class:
            return False
        
        tool_cwe_class = str(tool_cwe_class).replace(' ', '')
        expected_cwe_class = str(expected_cwe_class).replace(' ', '')
        
        tool_set = set(tool_cwe_class.split(',')) if ',' in tool_cwe_class else {tool_cwe_class}
        expected_set = set(expected_cwe_class.split(',')) if ',' in expected_cwe_class else {expected_cwe_class}
        
        return len(tool_set & expected_set) > 0

    def evaluate_detection(
        self,
        cve_info: CVEInfo,
        vul_findings: list[Finding],
        patch_findings: list[Finding],
        expected_cwe: str,
        vul_time: float,
        patch_time: float
    ) -> CVETestResult:
        """Evaluate detection using 4 scenarios from FSE 2023 paper"""
        expected_files = {m.file_path for m in cve_info.vulnerable_methods}
        expected_methods = cve_info.vulnerable_methods
        expected_cwe_class = expected_cwe
        
        sf_a = False
        sf_c = False
        sm_a = False
        sm_c = False

        for finding in vul_findings:
            # Get CWE class from rule ID (Horusec doesn't provide CWE directly)
            finding_cwe_class = self.get_cwe_class_from_rule(finding.rule_id)
        
            if finding.file_path in expected_files:
                sf_a = True
                if self.cwe_tp(finding_cwe_class, expected_cwe_class):
                    sf_c = True

            for method in expected_methods:
                if finding.file_path == method.file_path:
                    sm_a = True
                    if self.cwe_tp(finding_cwe_class, expected_cwe_class):
                        sm_c = True

        return CVETestResult(
            cve_id=cve_info.cve_id,
            project_name=cve_info.project_name,
            detected_in_vulnerable=len(vul_findings) > 0,
            detected_in_patched=len(patch_findings) > 0,
            SF_A=sf_a,
            SF_C=sf_c,
            SM_A=sm_a,
            SM_C=sm_c,
            vulnerable_findings=vul_findings,
            patched_findings=patch_findings,
            expected_cwe=expected_cwe,
            scan_time_vulnerable=vul_time,
            scan_time_patched=patch_time
        )
