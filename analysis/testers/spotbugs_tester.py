"""
SpotBugs with FindSecBugs Tester Implementation
Analyzes compiled Java bytecode for security vulnerabilities
"""
import os
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
import pandas as pd
from pathlib import Path
from typing import List, Tuple, Optional, Dict

from sympy import content

from testers.base_tester import BaseTester
from testers.utils import Finding

class SpotBugsTester(BaseTester):
    """
    SpotBugs with FindSecBugs plugin implementation
    Requires:
    - SpotBugs installation
    - FindSecBugs plugin JAR
    - Java compiler (javac)
    """

    def __init__(self):
        super().__init__("SpotBugs")
        self.spotbugs_cwe_mapping = self.load_spotbugs_cwe_mapping()

        # Try to locate SpotBugs and FindSecBugs
        self.spotbugs_jar = self.find_spotbugs_jar()
        self.findsecbugs_jar = self.find_findsecbugs_jar()

    def find_spotbugs_jar(self) -> Optional[str]:
        """Locate SpotBugs JAR file"""
        # Check environment variable
        spotbugs_home = os.environ.get('SPOTBUGS_HOME')
        if spotbugs_home:
            jar_path = Path(spotbugs_home) / 'lib' / 'spotbugs.jar'
            if jar_path.exists():
                return str(jar_path)

        # Check hardcoded path
        exact_path = '/Users/ibrahimmalik/Documents/code_tests/code-analysis/spotbugs/spotbugs-4.9.8/lib/spotbugs.jar'
        if Path(exact_path).exists():
            return exact_path

        # Try common installation locations
        common_paths = [
            Path.home() / 'spotbugs' / 'lib' / 'spotbugs.jar',
            Path('/usr/local/spotbugs/lib/spotbugs.jar'),
            Path('/opt/spotbugs/lib/spotbugs.jar'),
        ]
        
        for path in common_paths:
            if path.exists():
                return str(path)

        return None

    def find_findsecbugs_jar(self) -> Optional[str]:
        """Locate FindSecBugs plugin JAR"""
        # Check SpotBugs plugin directory
        spotbugs_home = os.environ.get('SPOTBUGS_HOME')
        if spotbugs_home:
            plugin_path = Path(spotbugs_home) / 'plugin' / 'findsecbugs-plugin.jar'
            if plugin_path.exists():
                return str(plugin_path)
            
        # Check hardcoded path
        exact_path = '/Users/ibrahimmalik/Documents/code_tests/code-analysis/spotbugs/spotbugs-4.9.8/plugin/findsecbugs-plugin-1.14.0.jar'
        if Path(exact_path).exists():
            return exact_path
        
        # Try common plugin locations
        if spotbugs_home:
            plugin_dir = Path(spotbugs_home) / 'plugin'
            if plugin_dir.exists():
                # Find any findsecbugs jar
                for jar in plugin_dir.glob('findsecbugs-plugin-*.jar'):
                    return str(jar)
        
        return None

    def load_spotbugs_cwe_mapping(self) -> Dict[str, str]:
        """
        Load SpotBugs bug pattern -> CWE-1000 class mapping
        CSV format: rule, cwe, cwe-1000
        Example: "Potential Command Injection (COMMAND_INJECTION),78,707"
        """
        csv_path = Path(__file__).parent.parent.parent / 'Real_world_vulnerability_dataset' / 'CWE_mapping' / 'SBwFSB_cwe.csv'

        if not csv_path.exists():
            print(f"Warning: {csv_path} not found")
            return {}

        try:
            df = pd.read_csv(csv_path, encoding='utf-8-sig') # Handle BOM
            mapping = {}

            for _, row in df.iterrows():
                rule = row['rule']
                cwe_class = row['cwe-1000']

                if pd.notna(rule) and pd.notna(cwe_class):
                    # Rule format: "Description (BUG_TYPE)"
                    if '(' in rule and ')' in rule:
                        bug_type = rule.split('(')[-1].split(')')[0].strip()
                    else:
                        bug_type = rule.strip()

                    # Normalize CWE class
                    cwe_str = str(cwe_class).strip()
                    if cwe_str.isdigit():
                        mapping[bug_type] = f"CWE-{cwe_str}"
                    elif cwe_str.startswith('CWE-'):
                        mapping[bug_type] = cwe_str

            print(f"Loaded {len(mapping)} SpotBugs/FindSecBugs rule mappings\n")
            return mapping

        except Exception as e:
            print(f"Error loading SpotBugs CWE mapping: {e}")
            return {}

    def get_cwe_class_from_rule(self, rule_id: str) -> Optional[str]:
        """Get CWE-1000 class from SpotBugs bug type"""
        return self.spotbugs_cwe_mapping.get(rule_id)

    def preprocess_java_file(self, content: str) -> str:
        """
        Preprocess Java code snippet for compilation
        Properly handles: package, imports, annotations, class declarations
        """
        lines = content.split('\n')
        
        # Skip leading empty/comment lines
        start = 0
        while start < len(lines):
            stripped = lines[start].strip()
            if stripped and not stripped.startswith('//') and not stripped.startswith('/*'):
                break
            start += 1
        
        lines = lines[start:]
        
        # Separate package, imports, and code
        package_line = None
        import_lines = []
        code_start = 0
        
        for i, line in enumerate(lines):
            stripped = line.strip()
            
            if stripped.startswith('package '):
                package_line = line
                code_start = i + 1
            elif stripped.startswith('import '):
                import_lines.append(line)
                code_start = i + 1
            elif stripped:  # Non-empty, non-package, non-import
                break
        
        # Get the actual code (from first non-package/import line)
        code_lines = lines[code_start:]
        
        # Build result
        result = []
        
        # Add imports (combine existing + our defaults)
        all_imports = set(import_lines)
        if 'import java.util.*;' not in ' '.join(import_lines):
            all_imports.add('import java.util.*;')
        if 'import java.io.*;' not in ' '.join(import_lines):
            all_imports.add('import java.io.*;')
        
        result.extend(sorted(all_imports))
        if all_imports:
            result.append('')  # Blank line after imports
        
        # Add the code
        result.extend(code_lines)
        
        # If no class found, wrap it
        code_str = '\n'.join(result)
        if not any(kw in code_str for kw in ['class ', 'interface ', 'enum ']):
            result = [
                'import java.util.*;',
                'import java.io.*;',
                '',
                'public class DummyWrapper {'
            ] + code_lines + ['}']
        
        return '\n'.join(result)

    def compile_java_files(self, source_dir: Path, output_dir: Path) -> bool:
        """
        Compile Java source files to bytecode
        SpotBugs analyzes .class files, not source code
        """
        java_files = list(source_dir.rglob("*.java"))

        if not java_files:
            print("No Java files to compile")
            return False

        try:
            # Preprocess all Java files first
            processed_files = []
            for java_file in java_files:
                with open(java_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Preprocess to fix snippet issues
                processed_content = self.preprocess_java_file(content)
                
                # Write back
                with open(java_file, 'w', encoding='utf-8') as f:
                    f.write(processed_content)
                
                processed_files.append(java_file)
            
            # Compile all Java files
            cmd = [
                "javac",
                "-d", str(output_dir),
                "-encoding", "UTF-8",
                "--release", "8",
                "-nowarn"
            ] + [str(f) for f in processed_files]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                print("Java compilation failed")
                print("STDOUT:")
                print(result.stdout)
                print("STDERR:")
                print(result.stderr)
                return False

            # Verify .class files were created
            class_files = list(output_dir.rglob("*.class"))
            if not class_files:
                print("No .class files were created after compilation")
                return False

            return True

        except subprocess.TimeoutExpired:
            print("Java compilation timed out")
            return False
        except FileNotFoundError:
            print(f"javac not found - Java compiler not installed")
            return False
        except Exception as e:
            print(f"Java compilation error: {e}")
            return False

    def run_scan(self, code_dir: Path) -> Tuple[List[Finding], float]:
        """
        Run SpotBugs with FindSecBugs on directory
        Steps:
        1. Compile Java source to bytecode
        2. Run SpotBugs with FindSecBugs plugin
        3. Parse XML output
        """
        start_time = time.time()

        # Check if tools are available
        if not self.spotbugs_jar:
            print(f"SpotBugs JAR not found. Set SPOTBUGS_HOME or install SpotBugs")
            return [], time.time() - start_time

        if not self.findsecbugs_jar:
            print(f"FindSecBugs plugin not found in SpotBugs plugin directory")
            return [], time.time() - start_time

        try:
            with tempfile.TemporaryDirectory() as temp_classes, \
                 tempfile.TemporaryDirectory() as temp_output:

                classes_dir = Path(temp_classes)
                output_file = Path(temp_output) / "spotbugs-results.xml"

                # Step 1: Compile Java source
                if not self.compile_java_files(code_dir, classes_dir):
                    # Compilation failed - normal for many snippets
                    print(f"Java compilation failed - skipping scan")
                    return [], time.time() - start_time

                # Step 2: Run SpotBugs with FindSecBugs
                cmd = [
                    "java", "-jar", self.spotbugs_jar,
                    "-textui",
                    "-pluginList", self.findsecbugs_jar,
                    "-xml:withMessages",
                    "-output", str(output_file),
                    "-effort:max", # Maximum analysis effort
                    "-low", # Report low priority bugs too
                    str(classes_dir)
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=180
                )

                scan_time = time.time() - start_time
                print(f"SpotBugs scan time: {scan_time:.2f} seconds")

                # SpotBugs returns 0 even with findings, 1 for some errors
                if result.returncode not in [0, 1]:
                    print(f"SpotBugs failed: {result.returncode}")
                    if result.stderr:
                        print(f"⚠ {result.stderr[:200]}")
                    return [], scan_time

                # Step 3: Parse XML output
                if output_file.exists():
                    findings = self.parse_output(output_file, code_dir)
                    return findings, scan_time
                else:
                    print(f"SpotBugs output file not found")
                    return [], scan_time

        except subprocess.TimeoutExpired:
            print(f"SpotBugs scan timeout")
            return [], time.time() - start_time
        except FileNotFoundError:
            print(f"java not found - Java runtime not installed")
            return [], 0.0
        except Exception as e:
            print(f"SpotBugs error: {e}")
            return [], time.time() - start_time

    def parse_output(self, xml_file: Path, code_dir: Path) -> List[Finding]:
        """
        Parse SpotBugs XML output to Finding objects
        """
        findings = []

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            # Parse each BugInstance
            for bug in root.findall('.//BugInstance'):
                bug_type = bug.get('type', '')
                priority = bug.get('priority', '2')

                # Get message
                short_msg = bug.find('ShortMessage')
                message = short_msg.text if short_msg is not None else bug_type

                # Get source location
                source_line = bug.find('SourceLine')
                if source_line is None:
                    continue

                source_path = source_line.get('sourcepath', '')
                start_line = int(source_line.get('start', 0))
                end_line = int(source_line.get('end', start_line))

                # Map priority to severity
                severity_map = {'1': 'HIGH', '2': 'MEDIUM', '3': 'LOW'}
                severity = severity_map.get(priority, 'MEDIUM')

                # SpotBugs doesn't include CWE in output
                # We'll map bug_type to CWE class via get_cwe_class_from_rule
                
                cwe_id = self.get_cwe_class_from_rule(bug_type)
                print(f"Debug: Bug type {bug_type} mapped to CWE {cwe_id}")
                finding = Finding(
                    file_path=source_path,
                    line_number=start_line,
                    end_line=end_line,
                    rule_id=bug_type,
                    cwe_id=cwe_id,
                    message=message,
                    severity=severity
                )
                findings.append(finding)

        except Exception as e:
            print(f"Error parsing SpotBugs XML: {e}")

        return findings
    