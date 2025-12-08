"""
Analyzes security tool results against OWASP Benchmark expectations
"""
import re
import json
from typing import Dict, List, Set, Tuple
from collections import defaultdict


class BenchmarkAnalyzer:
    """Analyzes OWASP Benchmark test results"""

    # Map common vulnerability names to OWASP Benchmark categories
    VULN_MAPPING = {
        # Command Injection
        'command injection': 'cmdi',
        'os command injection': 'cmdi',
        'code injection': 'cmdi',

        # SQL Injection
        'sql injection': 'sqli',
        'sql': 'sqli',

        # XSS
        'cross-site scripting': 'xss',
        'xss': 'xss',
        'reflected xss': 'xss',

        # Path Traversal
        'path traversal': 'pathtraver',
        'directory traversal': 'pathtraver',
        'path manipulation': 'pathtraver',

        # LDAP Injection
        'ldap injection': 'ldapi',
        'ldap': 'ldapi',

        # XPath Injection
        'xpath injection': 'xpathi',
        'xpath': 'xpathi',

        # Crypto Issues
        'weak cryptography': 'crypto',
        'insecure cryptographic': 'crypto',
        'cryptographic issues': 'crypto',

        # Weak Random
        'weak random': 'weakrand',
        'insecure random': 'weakrand',
        'predictable random': 'weakrand',

        # Hash Issues
        'weak hash': 'hash',
        'insecure hash': 'hash',
        'hash': 'hash',

        # Trust Boundary
        'trust boundary': 'trustbound',
        'trust boundary violation': 'trustbound',

        # Secure Cookie
        'secure cookie': 'securecookie',
        'cookie security': 'securecookie',
        'insecure cookie': 'securecookie',
    }

    def __init__(self, benchmark_file: str = "merged_output.java"):
        """Initialize analyzer with benchmark file"""
        self.benchmark_file = benchmark_file
        self.test_cases = {}
        self.vulnerability_counts = defaultdict(int)

    def extract_test_cases(self):
        """Extract test case information from benchmark file"""
        print(f"Analyzing benchmark file: {self.benchmark_file}")

        with open(self.benchmark_file, 'r') as f:
            content = f.read()

        # Pattern to match test case classes and their servlet mappings
        # Example: @WebServlet(value = "/sqli-00/BenchmarkTest00001")
        servlet_pattern = r'@WebServlet\(value\s*=\s*"/([\w-]+)/BenchmarkTest(\d+)"\)'
        matches = re.findall(servlet_pattern, content)

        for vuln_type, test_num in matches:
            test_id = f"BenchmarkTest{test_num}"
            self.test_cases[test_id] = {
                'test_number': int(test_num),
                'vulnerability_type': vuln_type,
                'servlet_path': f"/{vuln_type}/BenchmarkTest{test_num}"
            }
            self.vulnerability_counts[vuln_type] += 1

        print(f"Found {len(self.test_cases)} test cases")
        print(f"\nVulnerability distribution in benchmark:")
        for vuln_type, count in sorted(self.vulnerability_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {vuln_type}: {count}")

        return self.test_cases

    def normalize_vuln_type(self, vuln_name: str) -> str:
        """Normalize vulnerability name to benchmark category"""
        vuln_lower = vuln_name.lower().strip()

        # Direct mapping
        if vuln_lower in self.VULN_MAPPING:
            return self.VULN_MAPPING[vuln_lower]

        # Partial matching
        for key, value in self.VULN_MAPPING.items():
            if key in vuln_lower:
                return value

        return vuln_lower

    def get_base_vuln_types(self) -> Dict[str, int]:
        """Get vulnerability counts grouped by base type (without variant suffix)"""
        base_counts = defaultdict(int)
        for vuln_type, count in self.vulnerability_counts.items():
            # Extract base type ('cmdi-00' -> 'cmdi')
            base_type = vuln_type.rsplit('-', 1)[0] if '-' in vuln_type else vuln_type
            base_counts[base_type] += count
        return dict(base_counts)

    def compare_tool_results(self, tool_name: str, tool_findings: Dict[str, int]) -> Dict[str, any]:
        """
        Compare tool findings against benchmark expectations
        """
        if not self.test_cases:
            self.extract_test_cases()

        # Normalize tool findings to benchmark categories
        normalized_findings = defaultdict(int)
        for vuln_name, count in tool_findings.items():
            normalized = self.normalize_vuln_type(vuln_name)
            normalized_findings[normalized] += count

        # Get base vulnerability type counts from benchmark
        base_vuln_counts = self.get_base_vuln_types()

        # Calculate metrics by base vulnerability type
        results_by_type = {}
        total_detected = 0
        total_expected = 0
        total_true_positives = 0
        total_false_positives = 0
        total_false_negatives = 0

        # Process base types
        all_types = set(base_vuln_counts.keys()) | set(normalized_findings.keys())

        for base_type in sorted(all_types):
            expected_count = base_vuln_counts.get(base_type, 0)
            detected_count = normalized_findings.get(base_type, 0)

            if expected_count > 0: # Only count types in the benchmark
                total_expected += expected_count
                total_detected += detected_count

                # Calculate TP, FP, FN
                true_positives = min(detected_count, expected_count)
                false_positives = max(0, detected_count - expected_count)
                false_negatives = max(0, expected_count - detected_count)

                total_true_positives += true_positives
                total_false_positives += false_positives
                total_false_negatives += false_negatives

                # Calculate precision and recall
                precision = true_positives / detected_count if detected_count > 0 else 0
                recall = true_positives / expected_count if expected_count > 0 else 0
                f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

                results_by_type[base_type] = {
                    'expected': expected_count,
                    'detected': detected_count,
                    'true_positives': true_positives,
                    'false_positives': false_positives,
                    'false_negatives': false_negatives,
                    'precision': round(precision, 3),
                    'recall': round(recall, 3),
                    'f1_score': round(f1_score, 3)
                }

        # Calculate overall metrics
        overall_precision = total_true_positives / total_detected if total_detected > 0 else 0
        overall_recall = total_true_positives / total_expected if total_expected > 0 else 0
        overall_f1 = 2 * (overall_precision * overall_recall) / (overall_precision + overall_recall) if (overall_precision + overall_recall) > 0 else 0

        # Identify unmapped findings (not in benchmark at all)
        unmapped = {k: v for k, v in normalized_findings.items() if k not in base_vuln_counts}

        return {
            'tool_name': tool_name,
            'total_expected': total_expected,
            'total_detected': total_detected,
            'total_true_positives': total_true_positives,
            'total_false_positives': total_false_positives,
            'total_false_negatives': total_false_negatives,
            'overall_precision': round(overall_precision, 3),
            'overall_recall': round(overall_recall, 3),
            'overall_f1_score': round(overall_f1, 3),
            'detection_rate': round(total_detected / total_expected, 3) if total_expected > 0 else 0,
            'results_by_vulnerability': results_by_type,
            'unmapped_findings': unmapped
        }

    def generate_report(self, comparison_results: Dict, output_file: str):
        """Generate a detailed analysis report"""
        report = []
        report.append(f"OWASP Benchmark Analysis Report: {comparison_results['tool_name']}")
        report.append("")

        report.append("OVERALL METRICS")
        report.append(f"Total Expected Vulnerabilities: {comparison_results['total_expected']}")
        report.append(f"Total Detected: {comparison_results['total_detected']}")
        report.append(f"True Positives: {comparison_results['total_true_positives']}")
        report.append(f"False Positives: {comparison_results['total_false_positives']}")
        report.append(f"False Negatives: {comparison_results['total_false_negatives']}")
        report.append(f"")
        report.append(f"Precision: {comparison_results['overall_precision']:.1%}")
        report.append(f"Recall: {comparison_results['overall_recall']:.1%}")
        report.append(f"F1 Score: {comparison_results['overall_f1_score']:.3f}")
        report.append(f"Detection Rate: {comparison_results['detection_rate']:.1%}")
        report.append("")

        report.append("RESULTS BY VULNERABILITY TYPE")
        report.append(f"{'Type':<15} {'Expected':>10} {'Detected':>10} {'TP':>8} {'FP':>8} {'FN':>8} {'Precision':>10} {'Recall':>10} {'F1':>8}")

        for vuln_type, metrics in sorted(comparison_results['results_by_vulnerability'].items()):
            report.append(
                f"{vuln_type:<15} "
                f"{metrics['expected']:>10} "
                f"{metrics['detected']:>10} "
                f"{metrics['true_positives']:>8} "
                f"{metrics['false_positives']:>8} "
                f"{metrics['false_negatives']:>8} "
                f"{metrics['precision']:>9.1%} "
                f"{metrics['recall']:>9.1%} "
                f"{metrics['f1_score']:>8.3f}"
            )

        if comparison_results['unmapped_findings']:
            report.append("")
            report.append("UNMAPPED FINDINGS (not in OWASP Benchmark)")
            for finding, count in comparison_results['unmapped_findings'].items():
                report.append(f"  {finding}: {count}")

        report.append("")

        report_text = "\n".join(report)
        with open(output_file, 'w') as f:
            f.write(report_text)

        print(report_text)
        print(f"\nReport saved to: {output_file}")

        # Save JSON version
        json_output = output_file.replace('.txt', '.json')
        with open(json_output, 'w') as f:
            json.dump(comparison_results, f, indent=2)
        print(f"JSON data saved to: {json_output}")

        return report_text

if __name__ == "__main__":
    analyzer = BenchmarkAnalyzer()
    analyzer.extract_test_cases()
