"""
Multi-Tool Comparison Script
"""
import json
from pathlib import Path
from typing import Dict

def load_tool_results(tools_dir: str = "reports") -> Dict:
    """Load analysis results for all tools"""
    results = {}
    reports_path = Path(tools_dir)

    if not reports_path.exists():
        print(f"Reports directory not found: {tools_dir}")
        return results

    # Find all *_analysis.json files
    for json_file in reports_path.glob("*_analysis.json"):
        tool_name = json_file.stem.replace("_analysis", "")
        try:
            with open(json_file, 'r') as f:
                results[tool_name] = json.load(f)
            print(f"Loaded results for: {tool_name}")
        except Exception as e:
            print(f"Error loading {json_file}: {e}")

    return results

def print_overall_comparison(results: Dict):
    """Print overall comparison table"""
    print("")
    print("OVERALL TOOL COMPARISON")
    print(f"{'Tool':<15} {'Detected':>10} {'Expected':>10} {'TP':>8} {'FP':>8} {'FN':>8} {'Precision':>10} {'Recall':>10} {'F1':>8}")

    # Sort by F1 score
    sorted_tools = sorted(results.items(), key=lambda x: x[1]['overall_f1_score'], reverse=True)

    for tool_name, data in sorted_tools:
        print(
            f"{tool_name.capitalize():<15} "
            f"{data['total_detected']:>10} "
            f"{data['total_expected']:>10} "
            f"{data['total_true_positives']:>8} "
            f"{data['total_false_positives']:>8} "
            f"{data['total_false_negatives']:>8} "
            f"{data['overall_precision']:>9.1%} "
            f"{data['overall_recall']:>9.1%} "
            f"{data['overall_f1_score']:>8.3f}"
        )

def print_detailed_comparison(results: Dict):
    """Print detailed per-vulnerability comparison"""
    print("")
    print("DETAILED VULNERABILITY COMPARISON")
    print("")

    # Get all vulnerability types
    all_vulns = set()
    for data in results.values():
        all_vulns.update(data['results_by_vulnerability'].keys())

    for vuln in sorted(all_vulns):
        print(f"\n---{vuln.upper()}---")
        print(f"{'Tool':<15} {'Expected':>10} {'Detected':>10} {'Recall':>10} {'Precision':>10} {'F1':>8}")
        print("-" * 65)

        # Sort by F1 score for this vulnerability
        vuln_results = []
        for tool, data in results.items():
            vuln_data = data['results_by_vulnerability'].get(vuln)
            if vuln_data:
                vuln_results.append((tool, vuln_data))

        vuln_results.sort(key=lambda x: x[1]['f1_score'], reverse=True)

        for tool, vuln_data in vuln_results:
            print(
                f"{tool.capitalize():<15} "
                f"{vuln_data['expected']:>10} "
                f"{vuln_data['detected']:>10} "
                f"{vuln_data['recall']:>9.1%} "
                f"{vuln_data['precision']:>9.1%} "
                f"{vuln_data['f1_score']:>8.3f}"
            )

def generate_summary_report(results: Dict, output_file: str):
    """Generate a summary report file"""
    summary = {
        'total_tools_compared': len(results),
        'tools': list(results.keys()),
        'overall_rankings': {
            'by_f1_score': sorted(
                [(k, v['overall_f1_score']) for k, v in results.items()],
                key=lambda x: x[1],
                reverse=True
            ),
            'by_recall': sorted(
                [(k, v['overall_recall']) for k, v in results.items()],
                key=lambda x: x[1],
                reverse=True
            ),
            'by_precision': sorted(
                [(k, v['overall_precision']) for k, v in results.items()],
                key=lambda x: x[1],
                reverse=True
            ),
        },
        'vulnerability_coverage': {},
    }

    # Calculate which tools are best for each vulnerability
    all_vulns = set()
    for data in results.values():
        all_vulns.update(data['results_by_vulnerability'].keys())

    for vuln in all_vulns:
        best_tool = None
        best_f1 = 0
        for tool, data in results.items():
            vuln_data = data['results_by_vulnerability'].get(vuln, {})
            f1 = vuln_data.get('f1_score', 0)
            if f1 > best_f1:
                best_f1 = f1
                best_tool = tool

        summary['vulnerability_coverage'][vuln] = {
            'best_tool': best_tool,
            'best_f1_score': best_f1
        }

    # Save to file
    with open(output_file, 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"\nSummary report saved to: {output_file}")

def main():
    print("SECURITY TOOLS COMPARISON - OWASP Benchmark Analysis")

    # Load all tool results
    results = load_tool_results("reports")

    # Print comparisons
    print_overall_comparison(results)
    print_detailed_comparison(results)

    # Generate summary report
    generate_summary_report(results, "./reports/comparison_summary.json")

    # Find best overall tool
    best_tool = max(results.items(), key=lambda x: x[1]['overall_f1_score'])
    print(f"\nBest Overall Tool: {best_tool[0].capitalize()} (F1: {best_tool[1]['overall_f1_score']:.3f})")

    # Find best tool for each category
    all_vulns = set()
    for data in results.values():
        all_vulns.update(data['results_by_vulnerability'].keys())

    print()

if __name__ == "__main__":
    main()
