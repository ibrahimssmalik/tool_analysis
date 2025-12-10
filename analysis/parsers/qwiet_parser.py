import json
from typing import Dict, List, Any
from collections import defaultdict


class QwietParser:
    """Parser for Qwiet security findings"""

    # Map Qwiet vulnerability names to OWASP Benchmark categories
    VULN_NAME_MAPPING = {
        'Command Injection': 'cmdi',
        'SQL Injection': 'sqli',
        'Cross-Site Scripting (XSS)': 'xss',
        'Path Traversal': 'pathtraver',
        'LDAP Injection': 'ldapi',
        'XPath Injection': 'xpathi',
        'Weak Cryptography': 'crypto',
        'Weak Random': 'weakrand',
        'Weak Hash': 'hash',
        'Trust Boundary Violation': 'trustbound',
        'Insecure Cookie': 'securecookie',
    }

    def __init__(self, findings_file: str):
        """Initialize parser with findings file path"""
        self.findings_file = findings_file
        self.raw_data = []
        self.parsed_data = {}

    def load(self):
        """Load findings from JSON file"""
        with open(self.findings_file, 'r') as f:
            self.raw_data = json.load(f)
        print(f"Loaded {len(self.raw_data)} finding entries from {self.findings_file}")

    def parse(self) -> Dict[str, Any]:
        """Parse the aggregated findings data into structured format"""
        if not self.raw_data:
            self.load()

        # Organize findings by key type
        organized = defaultdict(dict)

        for entry in self.raw_data:
            finding_type = entry.get('finding_type', 'unknown')
            key = entry.get('key', 'unknown')
            value = entry.get('value', 'unknown')
            count = entry.get('count', 0)

            # Store in nested structure
            if finding_type not in organized:
                organized[finding_type] = {}
            if key not in organized[finding_type]:
                organized[finding_type][key] = {}

            organized[finding_type][key][value] = count

        self.parsed_data = dict(organized)
        return self.parsed_data

    def normalize_vuln_name(self, vuln_name: str) -> str:
        """
        Map Qwiet vulnerability name to benchmark category
        """
        return self.VULN_NAME_MAPPING.get(vuln_name, vuln_name.lower().replace(' ', '_'))

    def get_vulnerability_summary(self, normalize=True) -> Dict[str, int]:
        """
        Extract vulnerability categories and their counts
        """
        if not self.parsed_data:
            self.parse()

        security_issues = self.parsed_data.get('security_issue', {})
        categories = security_issues.get('category', {})

        if normalize:
            # Map to benchmark categories
            normalized = defaultdict(int)
            for vuln_name, count in categories.items():
                benchmark_cat = self.normalize_vuln_name(vuln_name)
                normalized[benchmark_cat] += count
            return dict(sorted(normalized.items(), key=lambda x: x[1], reverse=True))
        else:
            return dict(sorted(categories.items(), key=lambda x: x[1], reverse=True))

    def get_cwe_distribution(self) -> Dict[str, int]:
        """Extract CWE categories and their counts"""
        if not self.parsed_data:
            self.parse()

        security_issues = self.parsed_data.get('security_issue', {})
        cwes = security_issues.get('cwe_category', {})

        return dict(sorted(cwes.items(), key=lambda x: x[1], reverse=True))

    def get_severity_distribution(self) -> Dict[str, int]:
        """Extract CVSS severity ratings and their counts"""
        if not self.parsed_data:
            self.parse()

        security_issues = self.parsed_data.get('security_issue', {})
        severities = security_issues.get('cvss_31_severity_rating', {})

        return dict(sorted(severities.items(), key=lambda x: x[1], reverse=True))

    def get_cvss_scores(self) -> Dict[str, int]:
        """Extract CVSS scores and their counts"""
        if not self.parsed_data:
            self.parse()

        security_issues = self.parsed_data.get('security_issue', {})
        scores = security_issues.get('cvss_score', {})

        # Convert keys to float for proper sorting
        sorted_scores = sorted(scores.items(), key=lambda x: float(x[0]), reverse=True)
        return dict(sorted_scores)

    def get_total_findings(self) -> int:
        """Calculate total number of security findings"""
        vuln_summary = self.get_vulnerability_summary()
        return sum(vuln_summary.values())

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics about the findings"""
        return {
            'total_findings': self.get_total_findings(),
            'vulnerability_categories': self.get_vulnerability_summary(),
            'cwe_distribution': self.get_cwe_distribution(),
            'severity_distribution': self.get_severity_distribution(),
            'cvss_scores': self.get_cvss_scores(),
        }

    def export_summary(self, output_file: str):
        """Export summary statistics to JSON file"""
        stats = self.get_statistics()
        with open(output_file, 'w') as f:
            json.dump(stats, f, indent=2)
        print(f"Summary exported to {output_file}")

if __name__ == "__main__":
    parser = QwietParser("results/qwiet/all_findings.json")
    parser.load()
    parser.parse()

    print("\n=== Qwiet Analysis Summary ===")
    print(f"\nTotal Security Findings: {parser.get_total_findings()}")

    print("\n--- Vulnerability Categories ---")
    for category, count in parser.get_vulnerability_summary().items():
        print(f"  {category}: {count}")

    print("\n--- Severity Distribution ---")
    for severity, count in parser.get_severity_distribution().items():
        print(f"  {severity.upper()}: {count}")

    print("\n--- Top CWE Categories ---")
    for cwe, count in list(parser.get_cwe_distribution().items())[:10]:
        print(f"  CWE-{cwe}: {count}")

    # Export full summary
    parser.export_summary("analysis/reports/qwiet_summary.json")
