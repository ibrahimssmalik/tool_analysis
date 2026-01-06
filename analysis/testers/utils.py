from dataclasses import dataclass

@dataclass
class MethodInfo:
    """Represents a vulnerable or patched method"""
    file_path: str
    start_line: int
    end_line: int
    method_name: str
    source_code: str

@dataclass
class CVEInfo:
    """Represents a CVE with vulnerable and patched versions"""
    cve_id: str
    project_name: str
    vulnerable_version: str
    patched_version: str
    vulnerable_methods: list[MethodInfo]
    patched_methods: list[MethodInfo]
    expected_cwe: str = None

@dataclass
class Finding:
    file_path: str
    line_number: int
    end_line: int
    rule_id: str
    cwe_id: str
    message: str
    severity: str

@dataclass
class CVETestResult:
    cve_id: str
    project_name: str
    detected_in_vulnerable: bool
    detected_in_patched: bool
    SF_A: bool
    SF_C: bool
    SM_A: bool
    SM_C: bool
    vulnerable_findings: list[Finding]
    patched_findings: list[Finding]
    expected_cwe: str
    scan_time_vulnerable: float
    scan_time_patched: float