import os
import sys
import json

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from analysis.parsers.qwiet_parser import QwietParser
from analysis.benchmark_analyzer import BenchmarkAnalyzer

def main():
    qwiet_results = os.path.join(project_root, "tool_analysis", "results", "qwiet", "all_findings.json")
    expected_results = os.path.join(project_root, "tool_analysis", "benchmark", "expectedresults.json")
    output_report_txt = os.path.join(project_root, "tool_analysis", "reports", "qwiet_analysis.txt")
    output_report_json = os.path.join(project_root, "tool_analysis", "reports", "qwiet_analysis.json")

    # Make output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_report_txt), exist_ok=True)
    os.makedirs(os.path.dirname(output_report_json), exist_ok=True)

    print("=" * 80)
    print("Qwiet Analysis with Accurate Metrics (Estimated)")
    print("=" * 80)

    # Parse Qwiet results
    print(f"\n1. Loading Qwiet results from: {qwiet_results}")
    parser = QwietParser(qwiet_results)
    parser.load()
    parser.parse()
    vuln_summary = parser.get_vulnerability_summary()

    total_findings = sum(vuln_summary.values())
    print(f"   Found {total_findings} total findings across {len(vuln_summary)} categories")
    print(f"\n   Breakdown:")
    for vuln_type, count in sorted(vuln_summary.items(), key=lambda x: x[1], reverse=True):
        print(f"     {vuln_type:<15} {count:4d}")

    # Initialize analyzer
    print(f"\n2. Loading expected results from: {expected_results}")
    analyzer = BenchmarkAnalyzer(expected_results)

    # Calculate metrics (estimated for aggregated data)
    print(f"\n3. Calculating confusion matrix metrics (estimated)")

    results = analyzer.analyze_aggregated_counts("Qwiet", vuln_summary)

    # Display results
    print("\n")
    analyzer.print_analysis(results)

    # Save results
    print(f"\n4. Saving results")

    # Save JSON
    with open(output_report_json, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"   JSON report: {output_report_json}")

    # Save text report
    with open(output_report_txt, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write(f"{results['tool_name']} - OWASP Benchmark Analysis (Estimated Metrics)\n")
        f.write("=" * 80 + "\n")

        overall = results['overall']
        f.write(f"Overall Results:\n")
        f.write(f"  Total Test Cases:     {overall['total_tests']:4d}\n")
        f.write(f"  Vulnerable Tests:     {overall['total_vulnerable']:4d} ({overall['total_vulnerable']/overall['total_tests']*100:.1f}%)\n")
        f.write(f"  Safe Tests:           {overall['total_safe']:4d} ({overall['total_safe']/overall['total_tests']*100:.1f}%)\n")
        f.write(f"  Tool Flagged:         {overall['total_flagged']:4d} ({overall['total_flagged']/overall['total_tests']*100:.1f}%)\n")
        f.write(f"\n  True Positives (TP):  {overall['tp']:4d} (estimated)\n")
        f.write(f"  False Positives (FP): {overall['fp']:4d} (estimated)\n")
        f.write(f"  True Negatives (TN):  {overall['tn']:4d} (estimated)\n")
        f.write(f"  False Negatives (FN): {overall['fn']:4d} (estimated)\n")
        f.write(f"\n  Precision:            {overall['precision']*100:5.1f}%\n")
        f.write(f"  Recall (TPR):         {overall['recall']*100:5.1f}%\n")
        f.write(f"  False Positive Rate:  {overall['fpr']*100:5.1f}%\n")
        f.write(f"  F1 Score:             {overall['f1_score']:.3f}\n")
        f.write(f"  Score (TPR - FPR):    {overall['score']:.3f}\n\n")

        f.write(f"\n{'Category':<15} {'Total':>6} {'Vuln':>6} {'Safe':>6} {'Flagged':>8} {'TP':>5} {'FP':>5} {'TN':>5} {'FN':>5} {'Prec':>6} {'Rec':>6} {'F1':>6}\n")
        f.write("-" * 100 + "\n")

        for vuln_type in sorted(results['by_category'].keys()):
            cat = results['by_category'][vuln_type]
            f.write(f"{vuln_type:<15} {cat['total_tests']:6d} {cat['vulnerable_tests']:6d} {cat['safe_tests']:6d} {cat['tool_flagged']:8d} "
                   f"{cat['tp']:5d} {cat['fp']:5d} {cat['tn']:5d} {cat['fn']:5d} "
                   f"{cat['precision']*100:5.1f}% {cat['recall']*100:5.1f}% {cat['f1_score']:6.3f}\n")

        f.write("=" * 80 + "\n")

    print(f"   Text report: {output_report_txt}")

if __name__ == "__main__":
    main()
