"""
Extract expected results from OWASP Benchmark HTML test files
"""

import os
from pathlib import Path
from collections import defaultdict
import json

def extract_test_case_id(html_file):
    """Extract test case ID from filename"""
    # BenchmarkTest00006.html -> BenchmarkTest00006
    return Path(html_file).stem

def is_safe_test(html_file):
    """Check if test case is safe (non-vulnerable) by looking for class="safe" """
    try:
        with open(html_file, 'r') as f:
            content = f.read()
            # Safe tests have class="safe" in their HTML
            return 'class="safe"' in content
    except Exception as e:
        print(f"Error reading {html_file}: {e}")
        return None

def get_vulnerability_category(folder_path):
    """Extract vulnerability category from folder name"""
    # cmdi-00 -> cmdi
    # sqli-02 -> sqli
    folder_name = os.path.basename(folder_path)
    return folder_name.rsplit('-', 1)[0] if '-' in folder_name else folder_name

def extract_all_expected_results(benchmark_dir):
    """Extract expected results from all test HTML files"""

    expected_results = {
        'vulnerable': defaultdict(list),  # vuln_type -> [test_ids]
        'safe': defaultdict(list),         # vuln_type -> [test_ids]
        'by_test_id': {},                  # test_id -> {'vuln_type': str, 'is_vulnerable': bool}
        'summary': {}
    }

    # Find all vulnerability category folders
    category_folders = []
    for item in os.listdir(benchmark_dir):
        item_path = os.path.join(benchmark_dir, item)
        if os.path.isdir(item_path) and '-' in item:
            category_folders.append(item_path)

    print(f"Found {len(category_folders)} vulnerability category folders")

    # Process each folder
    for folder_path in sorted(category_folders):
        vuln_type = get_vulnerability_category(folder_path)
        html_files = list(Path(folder_path).glob('*.html'))

        for html_file in html_files:
            test_id = extract_test_case_id(html_file)
            is_safe = is_safe_test(html_file)

            if is_safe is None:
                continue

            if is_safe:
                expected_results['safe'][vuln_type].append(test_id)
            else:
                expected_results['vulnerable'][vuln_type].append(test_id)

            # Store by test ID for quick lookup
            expected_results['by_test_id'][test_id] = {
                'vuln_type': vuln_type,
                'is_vulnerable': not is_safe
            }

    # Calculate summary after processing all folders (aggregate by vuln_type)
    for vuln_type in set(expected_results['vulnerable'].keys()) | set(expected_results['safe'].keys()):
        vuln_count = len(expected_results['vulnerable'][vuln_type])
        safe_count = len(expected_results['safe'][vuln_type])
        total = vuln_count + safe_count

        expected_results['summary'][vuln_type] = {
            'total': total,
            'vulnerable': vuln_count,
            'safe': safe_count
        }

        print(f"  {vuln_type:<15} - Total: {total:4d}, Vulnerable: {vuln_count:4d}, Safe: {safe_count:4d}")

    return expected_results

def save_expected_results(expected_results, output_file):
    """Save expected results to JSON file"""
    # Convert defaultdict to regular dict for JSON serialization
    output_data = {
        'vulnerable': {k: sorted(v) for k, v in expected_results['vulnerable'].items()},
        'safe': {k: sorted(v) for k, v in expected_results['safe'].items()},
        'by_test_id': expected_results['by_test_id'],
        'summary': expected_results['summary']
    }

    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)

    print(f"\nExpected results saved to: {output_file}")

def print_summary(expected_results):
    """Print summary statistics"""
    print("\n" + "=" * 80)
    print("OWASP Benchmark Expected Results Summary")
    print("=" * 80)

    total_tests = len(expected_results['by_test_id'])
    total_vulnerable = sum(len(v) for v in expected_results['vulnerable'].values())
    total_safe = sum(len(v) for v in expected_results['safe'].values())

    print(f"\nTotal Test Cases: {total_tests}")
    print(f"Total Vulnerable: {total_vulnerable} ({total_vulnerable/total_tests*100:.1f}%)")
    print(f"Total Safe:       {total_safe} ({total_safe/total_tests*100:.1f}%)")

    print("\nBreakdown by Vulnerability Type:")
    print("-" * 80)
    print(f"{'Category':<15} {'Total':>8} {'Vulnerable':>12} {'Safe':>8} {'Vuln %':>10}")
    print("-" * 80)

    for vuln_type in sorted(expected_results['summary'].keys()):
        summary = expected_results['summary'][vuln_type]
        vuln_pct = summary['vulnerable'] / summary['total'] * 100 if summary['total'] > 0 else 0
        print(f"{vuln_type:<15} {summary['total']:8d} {summary['vulnerable']:12d} {summary['safe']:8d} {vuln_pct:9.1f}%")

    print("=" * 80)

if __name__ == "__main__":
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    benchmark_dir = os.path.join(project_root, "tool_analysis", "target", "benchmark")
    output_file = os.path.join(project_root, "tool_analysis", "benchmark", "expectedresults.json")

    print("Extracting expected results from OWASP Benchmark HTML files...")
    print(f"Benchmark directory: {benchmark_dir}")
    print("=" * 80)

    # Extract results
    expected_results = extract_all_expected_results(benchmark_dir)

    # Print summary
    print_summary(expected_results)

    # Save to file
    save_expected_results(expected_results, output_file)