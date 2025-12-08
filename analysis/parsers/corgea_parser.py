import json
from typing import Dict, List, Any
from collections import defaultdict


class CorgeaParser:
    """Parser for Corgea security findings"""

    # Map CWE IDs to OWASP Benchmark categories
    CWE_TO_BENCHMARK = {
        # SQL Injection
        'CWE-89': 'sqli',

        # XSS
        'CWE-79': 'xss',
        'CWE-80': 'xss',

        # Command Injection
        'CWE-78': 'cmdi',

        # Path Traversal
        'CWE-22': 'pathtraver',
        'CWE-23': 'pathtraver',
        'CWE-36': 'pathtraver',

        # LDAP Injection
        'CWE-90': 'ldapi',

        # XPath Injection
        'CWE-643': 'xpathi',

        # Weak Cryptography
        'CWE-327': 'crypto',
        'CWE-326': 'crypto',
        'CWE-328': 'crypto',

        # Weak Random
        'CWE-338': 'weakrand',
        'CWE-330': 'weakrand',

        # Weak Hash
        'CWE-328': 'hash',
        'CWE-916': 'hash',

        # Trust Boundary
        'CWE-501': 'trustbound',

        # Secure Cookie
        'CWE-614': 'securecookie',
        'CWE-1004': 'securecookie',
    }

    def __init__(self, findings_file: str):
        """Initialize parser with findings file path"""
        self.findings_file = findings_file
        self.raw_data = None
        self.parsed_findings = []

    def load(self):
        """Load findings from JSON file"""
        with open(self.findings_file, 'r') as f:
            self.raw_data = json.load(f)
        print(f"Loaded {len(self.raw_data.get('issues', []))} issues from {self.findings_file}")

    def parse(self) -> List[Dict[str, Any]]:
        """Parse Corgea findings into structured format"""
        if self.raw_data is None:
            self.load()

        findings = []
        issues = self.raw_data.get('issues', [])

        for issue in issues:
            classification = issue.get('classification', {})
            location = issue.get('location', {})
            file_info = location.get('file', {})

            finding = {
                'id': issue.get('id'),
                'cwe_id': classification.get('id', 'unknown'),
                'cwe_name': classification.get('name', 'unknown'),
                'description': classification.get('description', ''),
                'urgency': issue.get('urgency', 'unknown'),
                'status': issue.get('status', 'unknown'),
                'file_name': file_info.get('name', 'unknown'),
                'file_path': file_info.get('path', 'unknown'),
                'line_number': location.get('line_number', 0),
                'false_positive': issue.get('auto_triage', {}).get('false_positive_detection', {}).get('status') == 'false_positive',
            }
            findings.append(finding)

        self.parsed_findings = findings
        return findings

    def normalize_cwe_to_benchmark(self, cwe_id: str) -> str:
        """
        Map CWE ID to benchmark category
        """
        return self.CWE_TO_BENCHMARK.get(cwe_id, cwe_id.lower())

    def get_vulnerability_summary(self) -> Dict[str, int]:
        """
        Get vulnerability counts by benchmark category
        """
        if not self.parsed_findings:
            self.parse()

        # Filter out false positives
        valid_findings = [f for f in self.parsed_findings if not f.get('false_positive', False)]

        vuln_counts = defaultdict(int)
        for finding in valid_findings:
            cwe_id = finding.get('cwe_id', 'unknown')
            benchmark_cat = self.normalize_cwe_to_benchmark(cwe_id)
            vuln_counts[benchmark_cat] += 1

        # Sort by count descending
        return dict(sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True))

    def get_cwe_distribution(self) -> Dict[str, int]:
        """Get distribution by CWE category"""
        if not self.parsed_findings:
            self.parse()

        valid_findings = [f for f in self.parsed_findings if not f.get('false_positive', False)]
        cwe_counts = defaultdict(int)

        for finding in valid_findings:
            cwe = finding.get('cwe_id', 'unknown')
            cwe_counts[cwe] += 1

        return dict(sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True))

    def get_urgency_distribution(self) -> Dict[str, int]:
        """Get distribution by urgency level"""
        if not self.parsed_findings:
            self.parse()

        valid_findings = [f for f in self.parsed_findings if not f.get('false_positive', False)]
        urgency_counts = defaultdict(int)

        for finding in valid_findings:
            urgency = finding.get('urgency', 'unknown')
            urgency_counts[urgency] += 1

        return dict(sorted(urgency_counts.items(), key=lambda x: x[1], reverse=True))

    def get_test_case_coverage(self) -> Dict[str, List[str]]:
        """
        Map findings to specific benchmark test cases
        """
        if not self.parsed_findings:
            self.parse()

        import re
        test_coverage = defaultdict(list)

        for finding in self.parsed_findings:
            if finding.get('false_positive'):
                continue

            file_name = finding.get('file_name', '')
            # Extract test case number from filename like BenchmarkTest00854.java
            match = re.match(r'BenchmarkTest(\d+)\.java', file_name)
            if match:
                test_id = f"BenchmarkTest{match.group(1)}"
                cwe_id = finding.get('cwe_id', 'unknown')
                test_coverage[test_id].append(cwe_id)

        return dict(test_coverage)

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics about the findings"""
        if not self.parsed_findings:
            self.parse()

        valid_findings = [f for f in self.parsed_findings if not f.get('false_positive', False)]
        false_positives = [f for f in self.parsed_findings if f.get('false_positive', False)]

        return {
            'total_issues': len(self.parsed_findings),
            'valid_findings': len(valid_findings),
            'false_positives': len(false_positives),
            'vulnerability_categories': self.get_vulnerability_summary(),
            'cwe_distribution': self.get_cwe_distribution(),
            'urgency_distribution': self.get_urgency_distribution(),
            'unique_files': len(set(f['file_name'] for f in valid_findings)),
            'test_cases_covered': len(self.get_test_case_coverage()),
        }

    def export_summary(self, output_file: str):
        """Export summary statistics to JSON file"""
        stats = self.get_statistics()
        with open(output_file, 'w') as f:
            json.dump(stats, f, indent=2)
        print(f"Summary exported to {output_file}")

if __name__ == "__main__":
    parser = CorgeaParser("results/corgea/corgea_report.json")
    parser.load()
    parser.parse()

    print("\n---Corgea Analysis Summary---")
    stats = parser.get_statistics()

    print(f"\nTotal Issues: {stats['total_issues']}")
    print(f"Valid Findings: {stats['valid_findings']}")
    print(f"False Positives: {stats['false_positives']}")
    print(f"Test Cases Covered: {stats['test_cases_covered']}")

    print("\n---Vulnerability Categories (Benchmark)---")
    for category, count in list(stats['vulnerability_categories'].items())[:10]:
        print(f"{category}: {count}")

    print("\n---Top CWE Categories---")
    for cwe, count in list(stats['cwe_distribution'].items())[:10]:
        print(f"{cwe}: {count}")

    print("\n---Urgency Distribution---")
    for urgency, count in stats['urgency_distribution'].items():
        print(f"{urgency}: {count}")
