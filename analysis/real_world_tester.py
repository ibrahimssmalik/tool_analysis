import json
from pathlib import Path
from typing import List, Dict, Optional

from real_world_parser import RealWorldCVEParser
from testers import SemgrepTester, HorusecTester
from testers.base_tester import BaseTester
from testers.utils import CVETestResult

class RealWorldTestRunner:
    def __init__(self, dataset_path: str):
        self.parser = RealWorldCVEParser(dataset_path)
        self.cve_cwe_mapping = self.load_cve_mapping()
        
        # Available tools
        self.available_tools = {
            'semgrep': SemgrepTester,
            'horusec': HorusecTester,
            # 'codeql': CodeQLTester,
            # 'snyk': SnykTester,
        }
    
    def load_cve_mapping(self) -> dict[str, str]:
        mapping_file = Path("../Real_world_vulnerability_dataset/cve_to_class_official.json")
        
        if mapping_file.exists():
            with open(mapping_file) as f:
                mapping = json.load(f)
                multi = sum(1 for v in mapping.values() if ',' in v)
                print(f"Loaded {len(mapping)} CVE mappings ({multi} with multiple classes)\n")
                return mapping
        
        print("Warning: cve_to_class_official.json not found\n")
        return {}
    
    def run_single_tool(self, tester: BaseTester, limit: Optional[int] = None) -> dict:
        """Run tests with a single tool"""
        cves = self.parser.parse_all_cves(limit=limit)
        print(f"Testing {len(cves)} CVEs with {tester.tool_name}")
        print("="*80)

        results = []
        for cve in cves:
            expected_cwe = self.cve_cwe_mapping.get(cve.cve_id)
            result = tester.test_cve(cve, expected_cwe=expected_cwe)
            results.append(result)

        metrics = self.calculate_metrics(results, tester.tool_name)
        
        return {
            'tool': tester.tool_name,
            'total_cves': len(cves),
            'results': [self.result_to_dict(r, tester.tool_name) for r in results],
            'metrics': metrics
        }
    
    def run_multiple_tools(self, tool_names: List[str], limit: Optional[int] = None) -> Dict[str, dict]:
        """
        Run tests with multiple tools
        """
        all_results = {}
        
        for tool_name in tool_names:
            if tool_name not in self.available_tools:
                print(f"Warning: Unknown tool '{tool_name}'. Available: {list(self.available_tools.keys())}")
                continue
            
            print(f"TESTING WITH {tool_name.upper()}\n")
            
            # Initialize tool
            tester = self.available_tools[tool_name]()
            
            # Run tests
            results = self.run_single_tool(tester, limit=limit)
            all_results[tool_name] = results
            
            # Save individual results
            self.save_results(results, tool_name)
        
        return all_results
    
    def run_all_tools(self, limit: Optional[int] = None) -> Dict[str, dict]:
        """Run tests with all available tools"""
        return self.run_multiple_tools(list(self.available_tools.keys()), limit=limit)

    def result_to_dict(self, result: CVETestResult, tool_name: str) -> dict:
        return {
            'cve_id': result.cve_id,
            'project_name': result.project_name,
            'detected_in_vulnerable': result.detected_in_vulnerable,
            'detected_in_patched': result.detected_in_patched,
            'SF_A': result.SF_A,
            'SF_C': result.SF_C,
            'SM_A': result.SM_A,
            'SM_C': result.SM_C,
            'findings_count_vulnerable': len(result.vulnerable_findings),
            'findings_count_patched': len(result.patched_findings),
            'scan_time_vulnerable': result.scan_time_vulnerable,
            'scan_time_patched': result.scan_time_patched
        }

    def calculate_metrics(self, results: List[CVETestResult], tool_name: str) -> dict:
        total = len(results)
        if total == 0:
            return {}

        sf_a_detected = sum(1 for r in results if r.SF_A)
        sf_c_detected = sum(1 for r in results if r.SF_C)
        sm_a_detected = sum(1 for r in results if r.SM_A)
        sm_c_detected = sum(1 for r in results if r.SM_C)
        false_positives = sum(1 for r in results if r.detected_in_patched and r.SM_C)

        cve_r = (sm_c_detected / total) * 100
        cve_r_patch = (false_positives / max(sm_c_detected, 1)) * 100
        avg_scan_time = sum(r.scan_time_vulnerable for r in results) / total

        return {
            'tool': tool_name,
            'CVE_R_percent': round(cve_r, 2),
            'CVE_Rpatch_percent': round(cve_r_patch, 2),
            'avg_scan_time_seconds': round(avg_scan_time, 2),
            'scenarios': {
                'SF_A': {'detected': sf_a_detected, 'total': total, 'rate': round(sf_a_detected/total*100, 2)},
                'SF_C': {'detected': sf_c_detected, 'total': total, 'rate': round(sf_c_detected/total*100, 2)},
                'SM_A': {'detected': sm_a_detected, 'total': total, 'rate': round(sm_a_detected/total*100, 2)},
                'SM_C': {'detected': sm_c_detected, 'total': total, 'rate': round(sm_c_detected/total*100, 2)}
            },
            'false_positives': false_positives,
            'total_detections': sm_c_detected
        }
    
    def save_results(self, results: dict, tool_name: str):
        """Save results for a single tool"""
        output_path = Path("../results/real_world")
        output_path.mkdir(parents=True, exist_ok=True)
        
        output_file = output_path / f"{tool_name.lower()}_test_results.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\nSaved: {output_file}")
    
    def print_summary(self, all_results: Dict[str, dict]):
        """Print comparison summary of all tools"""
        print("\n")
        print("SUMMARY - ALL TOOLS")
        
        # Print table header
        print(f"\n{'Tool':<15} {'SM-C':<10} {'SF-C':<10} {'SM-A':<10} {'SF-A':<10} {'Avg Time':<10}")
        
        # Print each tool's results
        for tool_name, results in all_results.items():
            metrics = results['metrics']
            scenarios = metrics['scenarios']
            
            sm_c = f"{scenarios['SM_C']['detected']}/{scenarios['SM_C']['total']} ({scenarios['SM_C']['rate']}%)"
            sf_c = f"{scenarios['SF_C']['detected']}/{scenarios['SF_C']['total']} ({scenarios['SF_C']['rate']}%)"
            sm_a = f"{scenarios['SM_A']['detected']}/{scenarios['SM_A']['total']} ({scenarios['SM_A']['rate']}%)"
            sf_a = f"{scenarios['SF_A']['detected']}/{scenarios['SF_A']['total']} ({scenarios['SF_A']['rate']}%)"
            avg_time = f"{metrics['avg_scan_time_seconds']}s"
            
            print(f"{tool_name:<15} {sm_c:<10} {sf_c:<10} {sm_a:<10} {sf_a:<10} {avg_time:<10}")
        
        print("\n")
        print("KEY: SM-C = Method-level Correct CWE (primary metric)")
        print("     SF-C = File-level Correct CWE")
        print("     SM-A = Method-level Any CWE")
        print("     SF-A = File-level Any CWE")

def main():
    runner = RealWorldTestRunner("../Real_world_vulnerability_dataset")
    
    # Test a single tool
    # tester = SemgrepTester()
    # results = runner.run_single_tool(tester, limit=10)
    
    # Test specific tools
    results = runner.run_multiple_tools(['semgrep','horusec'], limit=10)
    
    # Test all available tools
    # results = runner.run_all_tools()
    
    # Print comparison
    runner.print_summary(results)

if __name__ == "__main__":
    main()
