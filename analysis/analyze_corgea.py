"""
Corgea Results Analysis Script
"""
import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from analysis.parsers.corgea_parser import CorgeaParser
from analysis.benchmark_analyzer import BenchmarkAnalyzer

def main():
    os.chdir(project_root)

    print("Corgea Results Analysis")
    print()

    # Parse Corgea results
    print("Step 1: Parsing Corgea findings")
    corgea_parser = CorgeaParser("../results/corgea/corgea_report.json")
    corgea_parser.load()
    corgea_parser.parse()

    # Get vulnerability summary
    vuln_summary = corgea_parser.get_vulnerability_summary()
    stats = corgea_parser.get_statistics()

    print(f"Found {stats['total_issues']} total issues")
    print(f"Valid findings: {stats['valid_findings']}")
    print(f"False positives: {stats['false_positives']}")
    print(f"Test cases covered: {stats['test_cases_covered']}")
    print()

    print("Corgea Vulnerability Detection (by Benchmark Category):")
    for category, count in vuln_summary.items():
        print(f"{category}: {count}")
    print()

    # Export detailed summary
    corgea_parser.export_summary("reports/corgea_summary.json")
    print()

    # Analyze against benchmark
    print("Step 2: Comparing against OWASP Benchmark")
    analyzer = BenchmarkAnalyzer("../merged_output.java")
    analyzer.extract_test_cases()
    print()

    # Compare results
    print("Step 3: Calculating metrics")
    comparison = analyzer.compare_tool_results("Corgea", vuln_summary)
    print()

    # Generate report
    print("Step 4: Generating analysis report")
    analyzer.generate_report(comparison, "reports/corgea_analysis.txt")
    print()

    print("Analysis Complete!")
    print()
    print("Generated files:")
    print("reports/corgea_summary.json")
    print("reports/corgea_analysis.txt")
    print("reports/corgea_analysis.json")
    print()

    # Show top detected categories
    print("Top Detected Vulnerability Types:")
    results_by_vuln = comparison['results_by_vulnerability']
    top_detected = sorted(
        [(k, v) for k, v in results_by_vuln.items() if v['detected'] > 0],
        key=lambda x: x[1]['f1_score'],
        reverse=True
    )[:10]

    for vuln_type, metrics in top_detected:
        print(f"  {vuln_type:<15} detected: {metrics['detected']:>3}, "
              f"recall: {metrics['recall']:>5.1%}, "
              f"precision: {metrics['precision']:>5.1%}, "
              f"F1: {metrics['f1_score']:.3f}")

    # Show missed categories
    missed = [(k, v) for k, v in results_by_vuln.items() if v['detected'] == 0]
    if missed:
        print()
        print("Not Detected:")
        for vuln_type, metrics in missed:
            print(f"  {vuln_type} (expected {metrics['expected']})")

    print()

if __name__ == "__main__":
    main()
