import json
import re
from collections import defaultdict
from typing import Dict, List, Set, Any

class BenchmarkAnalyzer:
    """Analyze security tool results against OWASP Benchmark with accurate metrics"""

    def __init__(self, expected_results_file: str):
        """
        Initialize with expected results file
        """
        self.expected_results_file = expected_results_file
        self.expected_results = None
        self.load_expected_results()

    def load_expected_results(self):
        """Load expected results from JSON file"""
        with open(self.expected_results_file, 'r') as f:
            self.expected_results = json.load(f)
        print(f"Loaded expected results for {len(self.expected_results['by_test_id'])} test cases")

    def get_test_ids_from_tool_results(self, tool_findings: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
        """
        Extract test case IDs from tool findings, grouped by vulnerability type
        """
        flagged_tests = defaultdict(set)

        for finding in tool_findings:
            # Extract test case ID from file path or other fields
            test_id = self._extract_test_id(finding)
            if test_id:
                vuln_type = finding.get('vuln_type', 'unknown')
                flagged_tests[vuln_type].add(test_id)

        return {k: set(v) for k, v in flagged_tests.items()}

    def _extract_test_id(self, finding: Dict[str, Any]) -> str:
        """Extract test case ID from finding"""
        # Try to extract from file_path
        if 'file_path' in finding:
            match = re.search(r'BenchmarkTest\d+', finding['file_path'])
            if match:
                return match.group(0)

        # Try other fields
        for field in ['test_id', 'location', 'file', 'path']:
            if field in finding:
                match = re.search(r'BenchmarkTest\d+', str(finding[field]))
                if match:
                    return match.group(0)

        return None

    def calculate_metrics(self, tool_name: str, flagged_tests: Dict[str, Set[str]]) -> Dict[str, Any]:
        """
        Calculate accurate confusion matrix metrics for tool results
        """
        results = {
            'tool_name': tool_name,
            'by_category': {},
            'overall': {}
        }

        # Get all vulnerability types from expected results
        all_vuln_types = set(self.expected_results['summary'].keys())

        # Calculate metrics for each vulnerability type
        total_tp = 0
        total_fp = 0
        total_tn = 0
        total_fn = 0

        for vuln_type in sorted(all_vuln_types):
            # Get expected vulnerable and safe test IDs for this category
            expected_vulnerable = set(self.expected_results['vulnerable'].get(vuln_type, []))
            expected_safe = set(self.expected_results['safe'].get(vuln_type, []))

            # Get test IDs flagged by the tool for this category
            tool_flagged = flagged_tests.get(vuln_type, set())

            # Calculate confusion matrix
            # TP: Tool flagged it AND it's actually vulnerable
            tp = len(tool_flagged & expected_vulnerable)

            # FP: Tool flagged it BUT it's actually safe
            fp = len(tool_flagged & expected_safe)

            # FN: Tool didn't flag it BUT it's actually vulnerable
            fn = len(expected_vulnerable - tool_flagged)

            # TN: Tool didn't flag it AND it's actually safe
            tn = len(expected_safe - tool_flagged)

            # Calculate metrics
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
            tpr = recall  # True Positive Rate = Recall
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0  # False Positive Rate

            # Store category results
            results['by_category'][vuln_type] = {
                'total_tests': len(expected_vulnerable) + len(expected_safe),
                'vulnerable_tests': len(expected_vulnerable),
                'safe_tests': len(expected_safe),
                'tool_flagged': len(tool_flagged),
                'tp': tp,
                'fp': fp,
                'tn': tn,
                'fn': fn,
                'precision': precision,
                'recall': recall,
                'tpr': tpr,
                'fpr': fpr,
                'f1_score': f1_score
            }

            total_tp += tp
            total_fp += fp
            total_tn += tn
            total_fn += fn

        # Calculate overall metrics
        overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
        overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
        overall_f1 = 2 * (overall_precision * overall_recall) / (overall_precision + overall_recall) if (overall_precision + overall_recall) > 0 else 0.0
        overall_tpr = overall_recall
        overall_fpr = total_fp / (total_fp + total_tn) if (total_fp + total_tn) > 0 else 0.0

        results['overall'] = {
            'total_tests': len(self.expected_results['by_test_id']),
            'total_vulnerable': sum(len(v) for v in self.expected_results['vulnerable'].values()),
            'total_safe': sum(len(v) for v in self.expected_results['safe'].values()),
            'total_flagged': sum(len(v) for v in flagged_tests.values()),
            'tp': total_tp,
            'fp': total_fp,
            'tn': total_tn,
            'fn': total_fn,
            'precision': overall_precision,
            'recall': overall_recall,
            'tpr': overall_tpr,
            'fpr': overall_fpr,
            'f1_score': overall_f1,
            'score': overall_tpr - overall_fpr  # Scorecard metric
        }

        return results

    def analyze_aggregated_counts(self, tool_name: str, vuln_counts: Dict[str, int]) -> Dict[str, Any]:
        """
        Analyze tools that only provide aggregated counts

        For tools without test case IDs, we can only estimate metrics.
        """
        results = {
            'tool_name': tool_name,
            'by_category': {},
            'overall': {}
        }

        total_tp = 0
        total_fp = 0
        total_tn = 0
        total_fn = 0

        for vuln_type, tool_count in vuln_counts.items():
            summary = self.expected_results['summary'].get(vuln_type, {})
            if not summary:
                continue

            expected_vulnerable = summary['vulnerable']
            expected_safe = summary['safe']
            total = summary['total']

            # Cap tool_count at total test cases (since multiple findings per test possible)
            # Assume if findings > total, it flagged all tests in category
            if tool_count > total:
                effective_flagged = total
                tp = expected_vulnerable
                fp = expected_safe
                fn = 0
                tn = 0
            elif tool_count >= expected_vulnerable:
                tp = expected_vulnerable
                fp = tool_count - expected_vulnerable
                fn = 0
                tn = expected_safe - fp
            else:
                tp = tool_count
                fp = 0
                fn = expected_vulnerable - tp
                tn = expected_safe
                effective_flagged = tool_count

            # Ensure non-negative
            tn = max(0, tn)
            fp = max(0, fp)
            effective_flagged = min(tool_count, total)

            # Calculate metrics
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
            tpr = recall
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

            results['by_category'][vuln_type] = {
                'total_tests': total,
                'vulnerable_tests': expected_vulnerable,
                'safe_tests': expected_safe,
                'tool_flagged_raw': tool_count, # Raw finding count from tool
                'tool_flagged': effective_flagged, # Estimated unique test cases flagged
                'tp': tp,
                'fp': fp,
                'tn': tn,
                'fn': fn,
                'precision': precision,
                'recall': recall,
                'tpr': tpr,
                'fpr': fpr,
                'f1_score': f1_score
            }

            total_tp += tp
            total_fp += fp
            total_tn += tn
            total_fn += fn

        # Calculate overall metrics
        overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
        overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
        overall_f1 = 2 * (overall_precision * overall_recall) / (overall_precision + overall_recall) if (overall_precision + overall_recall) > 0 else 0.0
        overall_tpr = overall_recall
        overall_fpr = total_fp / (total_fp + total_tn) if (total_fp + total_tn) > 0 else 0.0

        results['overall'] = {
            'total_tests': len(self.expected_results['by_test_id']),
            'total_vulnerable': sum(len(v) for v in self.expected_results['vulnerable'].values()),
            'total_safe': sum(len(v) for v in self.expected_results['safe'].values()),
            'total_flagged': sum(vuln_counts.values()),
            'tp': total_tp,
            'fp': total_fp,
            'tn': total_tn,
            'fn': total_fn,
            'precision': overall_precision,
            'recall': overall_recall,
            'tpr': overall_tpr,
            'fpr': overall_fpr,
            'f1_score': overall_f1,
            'score': overall_tpr - overall_fpr
        }

        return results

    def print_analysis(self, results: Dict[str, Any]):
        """Print formatted analysis results"""
        print("=" * 80)
        print(f"{results['tool_name']} - OWASP Benchmark Analysis")
        print("=" * 80)

        if 'note' in results:
            print(f"\nNote: {results['note']}")

        # Overall metrics
        overall = results['overall']
        print(f"\nOverall Results:")
        print(f"  Total Test Cases:     {overall['total_tests']:4d}")
        print(f"  Vulnerable Tests:     {overall['total_vulnerable']:4d} ({overall['total_vulnerable']/overall['total_tests']*100:.1f}%)")
        print(f"  Safe Tests:           {overall['total_safe']:4d} ({overall['total_safe']/overall['total_tests']*100:.1f}%)")
        print(f"  Tool Flagged:         {overall['total_flagged']:4d} ({overall['total_flagged']/overall['total_tests']*100:.1f}%)")
        print(f"\n  True Positives (TP):  {overall['tp']:4d}")
        print(f"  False Positives (FP): {overall['fp']:4d}")
        print(f"  True Negatives (TN):  {overall['tn']:4d}")
        print(f"  False Negatives (FN): {overall['fn']:4d}")
        print(f"\n  Precision:            {overall['precision']*100:5.1f}%")
        print(f"  Recall (TPR):         {overall['recall']*100:5.1f}%")
        print(f"  False Positive Rate:  {overall['fpr']*100:5.1f}%")
        print(f"  F1 Score:             {overall['f1_score']:.3f}")
        print(f"  Score (TPR - FPR):    {overall['score']:.3f}")

        # By category
        print(f"\n{'Category':<15} {'Total':>6} {'Vuln':>6} {'Safe':>6} {'Flagged':>8} {'TP':>5} {'FP':>5} {'TN':>5} {'FN':>5} {'Prec':>6} {'Rec':>6} {'F1':>6}")
        print("-" * 100)

        for vuln_type in sorted(results['by_category'].keys()):
            cat = results['by_category'][vuln_type]
            print(f"{vuln_type:<15} {cat['total_tests']:6d} {cat['vulnerable_tests']:6d} {cat['safe_tests']:6d} {cat['tool_flagged']:8d} "
                  f"{cat['tp']:5d} {cat['fp']:5d} {cat['tn']:5d} {cat['fn']:5d} "
                  f"{cat['precision']*100:5.1f}% {cat['recall']*100:5.1f}% {cat['f1_score']:6.3f}")

        print("=" * 80)
