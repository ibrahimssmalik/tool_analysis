"""
Base tester class for all security testing tools
Provides common functionality to avoid code duplication
"""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Tuple
import tempfile

from testers.utils import Finding, CVETestResult, CVEInfo, MethodInfo

class BaseTester(ABC):
    """Abstract base class for security testing tools"""
    
    def __init__(self, tool_name: str):
        self.tool_name = tool_name
    
    @abstractmethod
    def run_scan(self, code_dir: Path) -> Tuple[List[Finding], float]:
        """
        Run the tool on a directory
        
        Returns:
            (findings, scan_time)
        """
        pass
    
    @abstractmethod
    def parse_output(self, output: dict, code_dir: Path) -> List[Finding]:
        """Parse tool output to standardized Finding objects"""
        pass
    
    @abstractmethod
    def get_cwe_class_from_rule(self, rule_id: str) -> Optional[str]:
        """Get CWE class from tool's rule ID"""
        pass
    
    def create_temp_file(self, method: MethodInfo, temp_dir: Path) -> Path:
        """Create temporary Java file from method info"""
        file_path = temp_dir / method.file_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(method.source_code)
        
        return file_path
    
    def test_cve(self, cve_info: CVEInfo, expected_cwe: Optional[str] = None) -> CVETestResult:
        """
        Test a CVE (shared logic across all tools)
        """
        print(f"  Testing {cve_info.cve_id} ({cve_info.project_name})...")

        with tempfile.TemporaryDirectory() as temp_vul, \
             tempfile.TemporaryDirectory() as temp_patch:

            temp_vul_path = Path(temp_vul)
            temp_patch_path = Path(temp_patch)

            for method in cve_info.vulnerable_methods:
                self.create_temp_file(method, temp_vul_path)

            vul_findings, vul_time = self.run_scan(temp_vul_path)

            patch_findings = []
            patch_time = 0.0
            if cve_info.patched_methods:
                for method in cve_info.patched_methods:
                    self.create_temp_file(method, temp_patch_path)
                patch_findings, patch_time = self.run_scan(temp_patch_path)

            result = self.evaluate_detection(
                cve_info, vul_findings, patch_findings, expected_cwe, vul_time, patch_time
            )
            return result
    
    @staticmethod
    def cwe_tp(tool_cwe_class: str, expected_cwe_class: str) -> bool:
        """Check if tool's CWE class matches expected (handles multiple)"""
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
        vul_findings: List[Finding],
        patch_findings: List[Finding],
        expected_cwe: Optional[str],
        vul_time: float,
        patch_time: float
    ) -> CVETestResult:
        """Evaluate detection using 4 scenarios"""
        expected_files = {m.file_path for m in cve_info.vulnerable_methods}
        expected_methods = cve_info.vulnerable_methods
        expected_cwe_class = expected_cwe
        
        sf_a = False
        sf_c = False
        sm_a = False
        sm_c = False

        for finding in vul_findings:
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
