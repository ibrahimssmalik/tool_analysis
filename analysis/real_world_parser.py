import json
import csv
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

from testers.utils import MethodInfo, CVEInfo

class RealWorldCVEParser:
    """Parser for Real-World CVE Dataset"""

    def __init__(self, dataset_path: str):
        self.dataset_path = Path(dataset_path)
        self.vul_info_path = self.dataset_path / "vul_info"
        self.patch_info_path = self.dataset_path / "patch_info"

    def parse_filename(self, filename: str) -> Tuple[str, str, str]:
        """
        Parse CVE filename format: {project}_{CVE-YYYY-NNNNN}_{version}.csv
        """
        # Remove .csv extension
        name = Path(filename).stem

        # Find CVE pattern: CVE-YYYY-NNNNN
        cve_pattern = r'(CVE-\d{4}-\d+)'
        match = re.search(cve_pattern, name)

        if not match:
            raise ValueError(f"No CVE ID found in filename: {filename}")

        cve_id = match.group(1)
        cve_start = match.start()

        # Extract project name (everything before CVE)
        project_name = name[:cve_start].rstrip('_')

        # Extract version (everything after CVE)
        version_start = match.end() + 1
        version = name[version_start:]

        return project_name, cve_id, version

    def parse_path_info(self, path_str: str) -> Tuple[str, int, int, str]:
        """
        Parse path format: "file.java:[start,end]:MethodName"
        """
        # Remove surrounding quotes if present
        path_str = path_str.strip('"')

        # Pattern: filepath:[start,end]:method_name
        pattern = r'^(.+):\[(\d+),(\d+)\]:(.+)$'
        match = re.match(pattern, path_str)

        if not match:
            # Fallback: try without method name
            pattern2 = r'^(.+):\[(\d+),(\d+)\]$'
            match2 = re.match(pattern2, path_str)
            if match2:
                file_path, start, end = match2.groups()
                return file_path, int(start), int(end), "Unknown"
            else:
                raise ValueError(f"Cannot parse path: {path_str}")

        file_path, start, end, method_name = match.groups()

        return file_path, int(start), int(end), method_name

    def parse_csv_file(self, csv_path: Path, is_vulnerable: bool = True) -> List[MethodInfo]:
        """
        Parse a single CVE CSV file
        """
        methods = []

        try:
            with open(csv_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)

                for row in reader:
                    # Determine column names based on file type
                    if is_vulnerable:
                        path_col = 'Vul_Path'
                        src_col = 'Vul_Src'
                    else:
                        path_col = 'Fix_Path'
                        src_col = 'Fix_Src'

                    path_info = row.get(path_col)
                    source_code = row.get(src_col, '')

                    if path_info:
                        try:
                            file_path, start_line, end_line, method_name = self.parse_path_info(path_info)

                            method = MethodInfo(
                                file_path=file_path,
                                start_line=start_line,
                                end_line=end_line,
                                method_name=method_name,
                                source_code=source_code
                            )
                            methods.append(method)

                        except ValueError as e:
                            print(f"Warning: Could not parse path in {csv_path}: {e}")
                            continue

        except Exception as e:
            print(f"Error reading {csv_path}: {e}")

        return methods

    def find_patch_file(self, project_name: str, cve_id: str) -> Optional[Path]:
        """
        Find corresponding patch file for a vulnerability
        """
        # Look for files matching pattern: {project}_{cve}_*.csv
        pattern = f"{project_name}_{cve_id}_*.csv"
        patch_files = list(self.patch_info_path.glob(pattern))

        if patch_files:
            return patch_files[0]
        
        return None

    def parse_cve(self, vul_csv_path: Path) -> CVEInfo:
        """
        Parse a complete CVE (vulnerable + patched versions)
        """
        # Parse filename
        project_name, cve_id, vul_version = self.parse_filename(vul_csv_path.name)

        # Parse vulnerable methods
        vul_methods = self.parse_csv_file(vul_csv_path, is_vulnerable=True)

        # Find and parse patch file
        patch_file = self.find_patch_file(project_name, cve_id)

        if patch_file:
            patch_methods = self.parse_csv_file(patch_file, is_vulnerable=False)
            _, _, patch_version = self.parse_filename(patch_file.name)
        else:
            patch_methods = []
            patch_version = None

        return CVEInfo(
            cve_id=cve_id,
            project_name=project_name,
            vulnerable_version=vul_version,
            patched_version=patch_version,
            vulnerable_methods=vul_methods,
            patched_methods=patch_methods
        )

    def parse_all_cves(self, limit: Optional[int] = None) -> List[CVEInfo]:
        """
        Parse all CVEs in the dataset
        """
        cves = []
        csv_files = sorted(self.vul_info_path.glob("*.csv"))

        if limit:
            csv_files = csv_files[:limit]

        print(f"Parsing {len(csv_files)} CVE files...")

        for csv_file in csv_files:
            try:
                cve_info = self.parse_cve(csv_file)
                cves.append(cve_info)
                print(f"{cve_info.cve_id} ({cve_info.project_name}): "
                      f"{len(cve_info.vulnerable_methods)} vulnerable, "
                      f"{len(cve_info.patched_methods)} patched methods")
            except Exception as e:
                print(f"Error parsing {csv_file.name}: {e}")

        return cves

    def get_statistics(self, cves: List[CVEInfo]) -> Dict:
        """
        Calculate dataset statistics
        """
        stats = {
            'total_cves': len(cves),
            'projects': len(set(cve.project_name for cve in cves)),
            'with_patches': sum(1 for cve in cves if cve.patched_methods),
            'total_vulnerable_methods': sum(len(cve.vulnerable_methods) for cve in cves),
            'total_patched_methods': sum(len(cve.patched_methods) for cve in cves),
            'projects_list': sorted(set(cve.project_name for cve in cves))
        }
        return stats

def main():
    """Test the parser on sample CVEs"""

    # Initialize parser
    parser = RealWorldCVEParser("/Users/ibrahimmalik/Documents/code_tests/code-analysis/tool_analysis_copy/Real_world_vulnerability_dataset")

    # Parse CVEs
    cves = parser.parse_all_cves()

    # Display statistics
    stats = parser.get_statistics(cves)

    print("--- DATASET STATISTICS ---")
    print(f"Total CVEs parsed: {stats['total_cves']}")
    print(f"Unique projects: {stats['projects']}")
    print(f"CVEs with patches: {stats['with_patches']}")
    print(f"Total vulnerable methods: {stats['total_vulnerable_methods']}")
    print(f"Total patched methods: {stats['total_patched_methods']}")
    print(f"\nProjects: {', '.join(stats['projects_list'][:10])}")

    # Display CVE details
    if cves:
        print(f"SAMPLE CVE DETAILS: {cves[0].cve_id}")
        cve = cves[0]
        print(f"Project: {cve.project_name}")
        print(f"Vulnerable version: {cve.vulnerable_version}")
        print(f"Patched version: {cve.patched_version}")
        print(f"\nVulnerable methods ({len(cve.vulnerable_methods)}):")
        
        for i, method in enumerate(cve.vulnerable_methods[:3], 1):
            print(f"{i}. {method.file_path}")
            print(f"Lines: {method.start_line}-{method.end_line}")
            print(f"Method: {method.method_name}")
            print(f"Code length: {len(method.source_code)} chars")

    # Save to JSON
    output = {
        'statistics': stats,
        'sample_cves': [
            {
                'cve_id': cve.cve_id,
                'project': cve.project_name,
                'vulnerable_methods': len(cve.vulnerable_methods),
                'patched_methods': len(cve.patched_methods)
            }
            for cve in cves
        ]
    }

    output_path = Path("../results/real_world")
    output_path.mkdir(parents=True, exist_ok=True)

    with open(output_path / "parser_test_results_complete.json", 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\nResults saved to: results/real_world/parser_test_results_complete.json")

if __name__ == "__main__":
    main()
