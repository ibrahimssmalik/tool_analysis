import subprocess
import json
import tempfile
import time
import requests
import pandas as pd
from pathlib import Path
from typing import List, Tuple, Optional, Dict
import shutil

from testers.base_tester import BaseTester
from testers.utils import Finding

class SonarQubeTester(BaseTester):
    """
    SonarQube implementation using local server
    
    Requirements:
    - SonarQube server running on localhost:9000
    - Maven (mvn) for project scanning
    - SonarQube authentication token (from account settings)
    """

    def __init__(self):
        super().__init__("SonarQube")
        self.sonar_cwe_mapping = self.load_sonar_cwe_mapping()
        
        # SonarQube server configuration
        self.sonar_host = "http://localhost:9000"
        self.sonar_token = self.get_sonar_token()
        
        # Check if SonarQube is available
        self.check_sonarqube_availability()

    def get_sonar_token(self) -> Optional[str]:
        """Get SonarQube authentication token from environment"""
        import os
        token = os.environ.get('SONAR_TOKEN')
        if not token:
            print("SONAR_TOKEN not set. Export your token:")
            print("export SONAR_TOKEN='your-token-here'")
        return token

    def check_sonarqube_availability(self) -> bool:
        """Check if SonarQube server is running"""
        try:
            response = requests.get(f"{self.sonar_host}/api/system/status", timeout=5)
            if response.status_code == 200:
                status = response.json().get('status')
                if status == 'UP':
                    print(f"SonarQube server is running")
                    return True
                else:
                    print(f"SonarQube server status: {status}")
            else:
                print(f"SonarQube server returned {response.status_code}")
        except requests.exceptions.RequestException:
            print(f"SonarQube server not reachable at {self.sonar_host}")
            print("Start it with: ~/sonarqube/bin/macosx-universal-64/sonar.sh start")
        return False

    def load_sonar_cwe_mapping(self) -> Dict[str, str]:
        """Load SonarQube rule key -> CWE-1000 class mapping"""
        csv_path = Path(__file__).parent.parent.parent / 'Real_world_vulnerability_dataset' / 'CWE_mapping' / 'sonar_secu.csv'

        if not csv_path.exists():
            print(f"Warning: {csv_path} not found")
            return {}

        try:
            df = pd.read_csv(csv_path, encoding='utf-8-sig')
            mapping = {}

            for _, row in df.iterrows():
                rule_key = row['key']
                cwe_class = row['cwe-1000']

                if pd.notna(rule_key) and pd.notna(cwe_class):
                    cwe_str = str(cwe_class).strip()
                    if cwe_str.isdigit():
                        mapping[rule_key] = f"CWE-{cwe_str}"
                    elif cwe_str.startswith('CWE-'):
                        mapping[rule_key] = cwe_str

            print(f"Loaded {len(mapping)} SonarQube rule mappings")
            return mapping

        except Exception as e:
            print(f"Error loading SonarQube CWE mapping: {e}")
            return {}

    def get_cwe_class_from_rule(self, rule_id: str) -> Optional[str]:
        """Get CWE-1000 class from SonarQube rule key"""
        # Ensure java: prefix
        if ':' not in rule_id:
            rule_id = f"java:{rule_id}"
        return self.sonar_cwe_mapping.get(rule_id)

    def create_maven_project(self, code_dir: Path, project_dir: Path) -> bool:
        """
        Create minimal Maven project structure for SonarQube scanning
        
        Structure:
        project/
        - pom.xml
        - sonar-project.properties
        - src/main/java/ [code files]
        """
        try:
            # Create directory structure
            src_dir = project_dir / "src" / "main" / "java"
            src_dir.mkdir(parents=True, exist_ok=True)

            # Copy Java files
            java_files = list(code_dir.rglob("*.java"))
            if not java_files:
                return False

            for java_file in java_files:
                # Preserve directory structure
                rel_path = java_file.relative_to(code_dir)
                dest = src_dir / rel_path
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(java_file, dest)

            # Create pom.xml
            pom_xml = """<?xml version="1.0" encoding="UTF-8"?>
                        <project xmlns="http://maven.apache.org/POM/4.0.0"
                                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
                                http://maven.apache.org/xsd/maven-4.0.0.xsd">
                            <modelVersion>4.0.0</modelVersion>
                            
                            <groupId>com.test</groupId>
                            <artifactId>cve-snippet</artifactId>
                            <version>1.0-SNAPSHOT</version>
                            <packaging>jar</packaging>
                            
                            <properties>
                                <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
                                <maven.compiler.source>1.8</maven.compiler.source>
                                <maven.compiler.target>1.8</maven.compiler.target>
                            </properties>
                            
                            <dependencies>
                                <!-- Common dependencies for Java web apps -->
                                <dependency>
                                    <groupId>javax.servlet</groupId>
                                    <artifactId>javax.servlet-api</artifactId>
                                    <version>3.1.0</version>
                                    <scope>provided</scope>
                                </dependency>
                            </dependencies>
                        </project>
                        """
            with open(project_dir / "pom.xml", 'w') as f:
                f.write(pom_xml)

            return True

        except Exception as e:
            print(f"Error creating Maven project: {e}")
            return False

    def run_scan(self, code_dir: Path) -> Tuple[List[Finding], float]:
        """
        Run SonarQube analysis on code directory
        
        Steps:
        1. Create Maven project structure
        2. Run Maven SonarQube scanner
        3. Fetch results via SonarQube API
        4. Delete project from SonarQube (cleanup)
        """
        start_time = time.time()

        if not self.sonar_token:
            print(f"SONAR_TOKEN not configured")
            return [], time.time() - start_time

        try:
            with tempfile.TemporaryDirectory() as temp_project:
                project_dir = Path(temp_project)
                project_key = f"cve-test-{int(time.time() * 1000)}"

                # Step 1: Create Maven project
                if not self.create_maven_project(code_dir, project_dir):
                    return [], time.time() - start_time

                # Step 2: Create sonar-project.properties
                sonar_props = f"""sonar.projectKey={project_key}
                                sonar.projectName=CVE Test
                                sonar.projectVersion=1.0
                                sonar.sources=src/main/java
                                sonar.sourceEncoding=UTF-8
                                sonar.java.source=1.8
                                """
                with open(project_dir / "sonar-project.properties", 'w') as f:
                    f.write(sonar_props)

                # Step 3: Run SonarQube scanner
                cmd = [
                    "mvn", "sonar:sonar",
                    f"-Dsonar.host.url={self.sonar_host}",
                    f"-Dsonar.login={self.sonar_token}",
                    f"-Dsonar.projectKey={project_key}",
                    "-q" # Quiet mode
                ]

                result = subprocess.run(
                    cmd,
                    cwd=project_dir,
                    capture_output=True,
                    text=True,
                    timeout=180
                )

                if result.returncode != 0:
                    # Maven/SonarQube scan failed - normal for code snippets
                    return [], time.time() - start_time

                # Wait for SonarQube to process results
                time.sleep(2)

                # Step 4: Fetch results via API
                findings = self.fetch_results_from_api(project_key, code_dir)

                # Step 5: Cleanup - delete project from SonarQube
                self.delete_project(project_key)

                scan_time = time.time() - start_time
                return findings, scan_time

        except subprocess.TimeoutExpired:
            print(f"SonarQube scan timeout")
            return [], time.time() - start_time
        except FileNotFoundError:
            print(f"mvn not found - Maven not installed")
            return [], 0.0
        except Exception as e:
            print(f"SonarQube error: {e}")
            return [], time.time() - start_time

    def fetch_results_from_api(self, project_key: str, code_dir: Path) -> List[Finding]:
        """
        Fetch analysis results from SonarQube API
        """
        findings = []

        try:
            # Fetch issues via API
            url = f"{self.sonar_host}/api/issues/search"
            params = {
                'componentKeys': project_key,
                'ps': 500, # Page size
                'statuses': 'OPEN,CONFIRMED,REOPENED'
            }

            response = requests.get(
                url,
                params=params,
                auth=(self.sonar_token, ''),
                timeout=10
            )

            if response.status_code != 200:
                print(f"API request failed: {response.status_code}")
                return []

            data = response.json()
            issues = data.get('issues', [])

            for issue in issues:
                rule_key = issue.get('rule', '')
                message = issue.get('message', '')
                severity = issue.get('severity', 'MAJOR')

                # Get location
                component = issue.get('component', '')
                # Component format: "project_key:src/main/java/path/File.java"
                file_path = component.split(':', 1)[1] if ':' in component else ''
                # Remove src/main/java prefix
                if file_path.startswith('src/main/java/'):
                    file_path = file_path[14:]

                # Get line numbers
                text_range = issue.get('textRange', {})
                start_line = text_range.get('startLine', issue.get('line', 0))
                end_line = text_range.get('endLine', start_line)

                # Convert severity
                severity_map = {
                    'BLOCKER': 'HIGH',
                    'CRITICAL': 'HIGH',
                    'MAJOR': 'MEDIUM',
                    'MINOR': 'LOW',
                    'INFO': 'LOW'
                }
                severity_level = severity_map.get(severity, 'MEDIUM')

                finding = Finding(
                    file_path=file_path,
                    line_number=start_line,
                    end_line=end_line,
                    rule_id=rule_key,
                    cwe_id=None, # Will be mapped via get_cwe_class_from_rule
                    message=message,
                    severity=severity_level
                )
                findings.append(finding)

        except Exception as e:
            print(f"Error fetching results: {e}")

        return findings

    def delete_project(self, project_key: str):
        """Delete temporary project from SonarQube"""
        try:
            url = f"{self.sonar_host}/api/projects/delete"
            data = {'project': project_key}

            requests.post(
                url,
                data=data,
                auth=(self.sonar_token, ''),
                timeout=5
            )
        except:
            pass

    def parse_output(self, output_data: Dict, code_dir: Path) -> List[Finding]:
        """
        This method is required by BaseTester but not used in SonarQube
        (we fetch results directly from API instead)
        """
        return []
