"""
CodeQL Tester Implementation
Uses CodeQL CLI to create database and analyze for security vulnerabilities
"""
import json
import subprocess
import tempfile
import time
import pandas as pd
from pathlib import Path
from typing import List, Tuple, Optional, Dict

from testers.base_tester import BaseTester
from testers.utils import Finding

class CodeQLTester(BaseTester):
    """CodeQL implementation using CLI with build-mode none for Java"""

    def __init__(self):
        super().__init__("CodeQL")
        self.codeql_cwe_mapping = self.load_codeql_cwe_mapping()

    def load_codeql_cwe_mapping(self) -> Dict[str, str]:
        """
        Load CodeQL CWE weakness -> CWE-1000 class mapping
        """
        xlsx_path = Path(__file__).parent.parent.parent / 'Real_world_vulnerability_dataset' / 'CWE_mapping' / 'CodeQL.xlsx'

        if not xlsx_path.exists():
            print(f"Warning: {xlsx_path} not found")
            return {}

        try:
            # Read Excel file - assume first sheet with columns 'cwe' and 'cwe-1000'
            df = pd.read_excel(xlsx_path, sheet_name=0)
            mapping = {}

            # Look for relevant columns (may be named differently)
            cwe_col = None
            cwe1000_col = None

            for col in df.columns:
                col_lower = str(col).lower()
                if 'cwe' in col_lower and '1000' not in col_lower and cwe_col is None:
                    cwe_col = col
                elif 'cwe' in col_lower and '1000' in col_lower and cwe1000_col is None:
                    cwe1000_col = col

            if cwe_col and cwe1000_col:
                for _, row in df.iterrows():
                    cwe = row[cwe_col]
                    cwe_class = row[cwe1000_col]

                    if pd.notna(cwe) and pd.notna(cwe_class):
                        # Normalize CWE format
                        cwe_str = str(cwe).strip()
                        if not cwe_str.startswith('CWE-'):
                            cwe_str = f"CWE-{cwe_str}"

                        # Handle cwe_class - may be single or comma-separated
                        classes = str(cwe_class).split(',')
                        first_class = classes[0].strip()
                        if first_class.isdigit():
                            mapping[cwe_str] = f"CWE-{first_class}"
                        elif first_class.startswith('CWE-'):
                            mapping[cwe_str] = first_class

            print(f"Loaded {len(mapping)} CodeQL CWE mappings")
            return mapping

        except Exception as e:
            print(f"Error loading CodeQL CWE mapping: {e}")
            return {}

    def get_cwe_class_from_rule(self, rule_id: str) -> Optional[str]:
        """
        Get CWE-1000 class from CWE weakness
        """
        # Normalize format
        if not rule_id.startswith('CWE-'):
            rule_id = f"CWE-{rule_id}"

        return self.codeql_cwe_mapping.get(rule_id)

    def run_scan(self, code_dir: Path) -> Tuple[List[Finding], float]:
        """
        Run CodeQL analysis on directory
        1. Create CodeQL database (build-mode none for Java)
        2. Analyze database with java security queries
        3. Parse SARIF output
        """
        start_time = time.time()

        try:
            with tempfile.TemporaryDirectory() as temp_db_dir:
                db_path = Path(temp_db_dir) / "codeql-db"
                sarif_output = Path(temp_db_dir) / "results.sarif"

                # Step 1: Create database (no build needed for code snippets)
                create_cmd = [
                    "codeql", "database", "create",
                    str(db_path),
                    "--language=java",
                    "--source-root", str(code_dir),
                    "--build-mode=none"
                ]

                create_result = subprocess.run(
                    create_cmd,
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                if create_result.returncode != 0:
                    print(f"      ⚠ CodeQL database creation failed: {create_result.returncode}")
                    if create_result.stderr:
                        print(f"      ⚠ Stderr: {create_result.stderr[:500]}")
                    return [], time.time() - start_time

                # Step 2: Analyze database with security queries
                analyze_cmd = [
                    "codeql", "database", "analyze",
                    str(db_path),
                    "codeql/java-queries:codeql-suites/java-security-extended.qls",
                    "--format=sarif-latest",
                    "--output", str(sarif_output),
                    "--threads=0"
                ]

                analyze_result = subprocess.run(
                    analyze_cmd,
                    capture_output=True,
                    text=True,
                    timeout=180
                )

                scan_time = time.time() - start_time

                if analyze_result.returncode != 0:
                    print(f"CodeQL analysis failed: {analyze_result.returncode}")
                    if analyze_result.stderr:
                        print(f"Stderr: {analyze_result.stderr[:500]}")
                    return [], scan_time

                # Step 3: Parse SARIF output
                if sarif_output.exists():
                    with open(sarif_output, 'r') as f:
                        sarif_data = json.load(f)

                    findings = self.parse_output(sarif_data, code_dir)
                    return findings, scan_time
                else:
                    print(f"SARIF output file not found")
                    return [], scan_time

        except subprocess.TimeoutExpired:
            print(f"CodeQL scan timeout")
            return [], time.time() - start_time
        except Exception as e:
            print(f"CodeQL error: {e}")
            return [], time.time() - start_time

    def parse_output(self, sarif_data: Dict, code_dir: Path) -> List[Finding]:
        """
        Parse CodeQL SARIF output to Finding objects
        """
        findings = []
        
        for run in sarif_data.get('runs', []):
            for result in run.get('results', []):
                # Extract rule ID
                rule_id = result.get('ruleId', '')
                
                # Extract location
                locations = result.get('locations', [])
                if not locations:
                    continue
                
                physical_location = locations[0].get('physicalLocation', {})
                artifact = physical_location.get('artifactLocation', {})
                region = physical_location.get('region', {})
                
                # Get file path
                file_uri = artifact.get('uri', '')
                # CodeQL URIs are like "file:///path/to/file.java" or just "path/to/file.java"
                if file_uri.startswith('file://'):
                    file_path = Path(file_uri[7:])  # Remove 'file://'
                else:
                    file_path = Path(file_uri)
                
                # Make relative to code_dir
                try:
                    rel_path = file_path.relative_to(code_dir)
                except ValueError:
                    # If already relative or not under code_dir
                    rel_path = file_path
                
                # Extract line numbers
                start_line = region.get('startLine', 0)
                end_line = region.get('endLine')
                
                # Extract CWE from tags
                cwe_id = None
                tags = result.get('properties', {}).get('tags', [])
                for tag in tags:
                    if tag.startswith('external/cwe/cwe-'):
                        # e.g., "external/cwe/cwe-089" -> "CWE-089"
                        cwe_num = tag.split('cwe-')[1]
                        cwe_id = f"CWE-{cwe_num.upper()}"
                        break
                
                # Extract message
                message_obj = result.get('message', {})
                message = message_obj.get('text', '')
                
                # Extract severity
                severity = result.get('properties', {}).get('problem.severity', 'warning')
                
                finding = Finding(
                    file_path=str(rel_path),
                    line_number=start_line,
                    end_line=end_line,
                    rule_id=rule_id,
                    cwe_id=cwe_id,
                    message=message,
                    severity=severity.upper()
                )
                findings.append(finding)
        
        return findings
