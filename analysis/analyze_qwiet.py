"""
Qwiet Results Analysis Script
"""
import sys
import os

from parsers.qwiet_parser import QwietParser
from benchmark_analyzer import BenchmarkAnalyzer


def main():
    print("Qwiet Results Analysis")
    print()

    # Parse Qwiet results
    print("Step 1: Parsing Qwiet findings")
    qwiet_parser = QwietParser("../results/qwiet/all_findings.json")
    qwiet_parser.load()
    qwiet_parser.parse()

    # Get vulnerability summary
    vuln_summary = qwiet_parser.get_vulnerability_summary()
    print(f"Found {qwiet_parser.get_total_findings()} total security issues")
    print()

    print("Qwiet Vulnerability Detection:")
    for category, count in vuln_summary.items():
        print(f"{category}: {count}")
    print()

    qwiet_parser.export_summary("reports/qwiet_summary.json")
    print()

    # Analyze against benchmark
    print("Step 2: Comparing against OWASP Benchmark")
    analyzer = BenchmarkAnalyzer("merged_output.java")
    analyzer.extract_test_cases()
    print()

    # Compare results
    print("Step 3: Calculating metrics")
    comparison = analyzer.compare_tool_results("Qwiet", vuln_summary)
    print()

    # Generate report
    print("Step 4: Generating analysis report")
    analyzer.generate_report(comparison, "reports/qwiet_analysis.txt")
    print()

    print("Analysis Complete!")
    print()
    print("Generated files:")
    print("reports/qwiet_summary.json")
    print("reports/qwiet_analysis.txt")
    print("reports/qwiet_analysis.json")
    print()


if __name__ == "__main__":
    main()
