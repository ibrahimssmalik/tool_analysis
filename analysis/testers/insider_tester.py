import subprocess
import json
import tempfile
import time
import pandas as pd
from pathlib import Path
from typing import List, Tuple, Optional, Dict

from testers.base_tester import BaseTester
from testers.utils import Finding

class InsiderTester(BaseTester):
    """
    Insider SAST implementation
    """

    def __init__(self):
        super().__init__("Insider")
        self.insider_cwe_mapping = self.load_insider_cwe_mapping()

    def load_insider_cwe_mapping(self) -> Dict[str, str]:
        """
        Load Insider CWE -> CWE-1000 class mapping
        CSV format: Rule num, CWE ID, CWE-1000
        """
        csv_path = Path('../Real_world_vulnerability_dataset/CWE_mapping/Insider.csv')

        if not csv_path.exists():
            print(f"Warning: {csv_path} not found")
            return {}

        try:
            df = pd.read_csv(csv_path, encoding='utf-8-sig')
            mapping = {}

            for _, row in df.iterrows():
                cwe_id = row['CWE ID']
                cwe_1000 = row['CWE-1000']

                if pd.notna(cwe_id) and pd.notna(cwe_1000):
                    # Normalize CWE ID format
                    cwe_str = str(cwe_id).strip()
                    if not cwe_str.startswith('CWE-'):
                        cwe_str = f"CWE-{cwe_str}"

                    # Handle CWE-1000 (may be comma-separated)
                    cwe_1000_str = str(cwe_1000).strip()
                    if ',' in cwe_1000_str:
                        # Take first value if multiple
                        cwe_1000_str = cwe_1000_str.split(',')[0].strip()

                    # Normalize CWE-1000 format
                    if cwe_1000_str.isdigit():
                        mapping[cwe_str] = f"CWE-{cwe_1000_str}"
                    elif cwe_1000_str.startswith('CWE-'):
                        mapping[cwe_str] = cwe_1000_str

            print(f"Loaded {len(mapping)} Insider CWE mappings")
            return mapping

        except Exception as e:
            print(f"Error loading Insider CWE mapping: {e}")
            return {}

    def get_cwe_class_from_rule(self, rule_id: str) -> Optional[str]:
        """
        Get CWE-1000 class from CWE weakness
        """
        # Normalize format
        if not rule_id.startswith('CWE-'):
            rule_id = f"CWE-{rule_id}"

        return self.insider_cwe_mapping.get(rule_id)

    def run_scan(self, code_dir: Path) -> Tuple[List[Finding], float]:
        """
        Run Insider analysis on directory
        Command: insider -tech java -target <dir>
        """
        start_time = time.time()

        # Check if Insider is available
        try:
            result = subprocess.run(
                ["insider", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
        except FileNotFoundError:
            print(f"Insider not found.")
            return [], time.time() - start_time

        try:
            with tempfile.TemporaryDirectory() as temp_output:
                output_dir = Path(temp_output)

                # Insider generates report.json in the working directory
                cmd = [
                    "insider",
                    "-tech", "java",
                    "-target", str(code_dir.absolute()),
                    "-no-html",
                    "-security", "0"
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=180,
                    cwd=str(output_dir)
                )

                scan_time = time.time() - start_time

                # Insider returns 0 even with findings
                if result.returncode != 0 and result.returncode != 1:
                    print(f"Insider failed: {result.returncode}")
                    if result.stderr:
                        print(f"Stderr: {result.stderr[:500]}")
                    return [], scan_time

                # Look for report.json
                report_file = output_dir / "report.json"
                if report_file.exists():
                    with open(report_file, 'r') as f:
                        report_data = json.load(f)

                    findings = self.parse_output(report_data, code_dir)
                    return findings, scan_time
                else:
                    print(f"Insider report.json not found")
                    # Check if there are any .json files
                    json_files = list(output_dir.glob("*.json"))
                    if json_files:
                        print(f"Found: {[f.name for f in json_files]}")
                    return [], scan_time

        except subprocess.TimeoutExpired:
            print(f"Insider scan timeout")
            return [], time.time() - start_time
        except Exception as e:
            print(f"Insider error: {e}")
            return [], time.time() - start_time

    def parse_output(self, report_data: Dict, code_dir: Path) -> List[Finding]:
        """
        Parse Insider JSON output to Finding objects
        Expected JSON structure (based on SAST standards):
        """
        findings = []

        try:
            # Try different JSON structures
            vulnerabilities = []

            # Pattern 1: "vulnerabilities" key
            if "vulnerabilities" in report_data:
                vulnerabilities = report_data["vulnerabilities"]
            # Pattern 2: "issues" key
            elif "issues" in report_data:
                vulnerabilities = report_data["issues"]
            # Pattern 3: Direct array
            elif isinstance(report_data, list):
                vulnerabilities = report_data
            # Pattern 4: Nested in results
            elif "results" in report_data:
                vulnerabilities = report_data["results"]

            for vuln in vulnerabilities:
                # Extract fields (try different key names)
                cwe = vuln.get("cwe", vuln.get("CWE", vuln.get("cweId", "")))
                title = vuln.get("title", vuln.get("name", vuln.get("message", "")))
                severity = vuln.get("severity", vuln.get("priority", "MEDIUM"))
                line = vuln.get("line", vuln.get("startLine", vuln.get("lineNumber", 0)))
                end_line = vuln.get("endLine", line)
                file_path = vuln.get("file", vuln.get("filePath", vuln.get("location", "")))

                # Normalize severity
                severity_map = {
                    "CRITICAL": "error",
                    "HIGH": "error",
                    "MEDIUM": "warning",
                    "LOW": "note",
                    "INFO": "note"
                }
                severity_level = severity_map.get(severity.upper(), "warning")

                # Get CWE class from CWE weakness
                cwe_class = ""
                if cwe:
                    cwe_class = self.get_cwe_class_from_rule(cwe) or ""

                # Make path relative
                if file_path.startswith(str(code_dir)):
                    file_path = str(Path(file_path).relative_to(code_dir))

                # Use CWE as rule_id if available
                rule_id = cwe if cwe else title

                findings.append(Finding(
                    file_path=file_path,
                    line_number=int(line) if line else 0,
                    end_line=int(end_line) if end_line else int(line) if line else 0,
                    rule_id=rule_id,
                    cwe_id=cwe,
                    message=title,
                    severity=severity_level
                ))

        except Exception as e:
            print(f"Error parsing Insider output: {e}")

        return findings
