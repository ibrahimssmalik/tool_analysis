import os
import json
import time
import pandas as pd
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from dotenv import load_dotenv
from langchain_ollama import ChatOllama
from litellm import completion, Timeout, RateLimitError, APIError
import re

# load environment variables
load_dotenv()

@dataclass
class LLMFinding:
    """Represents a vulnerability found by LLM"""
    test_name: str
    detected: bool
    detected_cwe: Optional[str]
    confidence: Optional[str]
    reasoning: Optional[str]
    response_time: float

class LLMSASTTester:
    """
    Tests LLMs on OWASP Benchmark for security vulnerability detection
    """
    
    def __init__(self, model_name: str, model_config: Optional[Dict] = None):
        """
        Initialize LLM tester
        """
        self.model_name = model_name
        self.model_config = model_config or {}
        self.model_id = self._get_model_id()
        
    def _get_model_id(self) -> str:
        """Get the actual model identifier for API calls"""
        models = {
            'gpt4': 'gpt-4-turbo-preview', # via API
            'gpt4o': 'gpt-4o', # via API
            'gpt-oss': 'gpt-oss:20b', # via Ollama
            'claude': 'claude-sonnet-4-20250514', # via API
            'claude-opus': 'claude-opus-4-20250514', # via API
            'deepseek': 'text-completion-openai/deepseek-ai/deepseek-coder-33b-instruct', # via RITS
            'granite': 'granite3.3', # via Ollama
            'qwen': 'qwen2.5-coder:32b' # via Ollama
        }
        return self.model_config.get('model_id', models.get(self.model_name, self.model_name))
    
    def create_prompt(self, code: str, test_name: str) -> str:
        """
        Create security analysis prompt for the LLM
        """
        prompt = f"""You are a security code analyzer. Analyze this Java code for security vulnerabilities.

                    Code from {test_name}:
                    ```java
                    {code}
                    ```

                    Task:
                    1. Identify if there is a security vulnerability in this code
                    2. If yes, classify it with the appropriate CWE ID (e.g., CWE-89 for SQL Injection)
                    3. Explain your reasoning briefly

                    Respond ONLY in this JSON format:
                    {{
                        "has_vulnerability": true/false,
                        "cwe_id": "CWE-XXX" or null,
                        "confidence": "high/medium/low",
                        "reasoning": "brief explanation"
                    }}

                    All string values MUST be single-line. Do NOT include newlines inside string values.
                    The "reasoning" field must be a single-line string.
                    Do not include any other text, markdown formatting, or code blocks. Only output the JSON.
                    """
        
        return prompt
    
    def repair_json(self, text: str) -> str:
        # Replace unescaped newlines inside strings
        repaired = []
        in_string = False
        escape = False

        for ch in text:
            if ch == '"' and not escape:
                in_string = not in_string
            if ch == '\n' and in_string:
                repaired.append('\\n')
            else:
                repaired.append(ch)
            escape = (ch == '\\' and not escape)

        return ''.join(repaired)

    def parse_llm_response(self, response_text: str) -> Dict:
        """
        Parse LLM's JSON response
        """
        try:
            # Remove markdown code blocks if present
            text = response_text.strip()
            
            # Method 1: Extract from ```json blocks
            if '```json' in text:
                text = text.split('```json')[1].split('```')[0].strip()
            elif '```' in text:
                text = text.split('```')[1].split('```')[0].strip()
            
            # Method 2: Find JSON object with regex - look for { ... } pattern
            import re
            json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text, re.DOTALL)
            if json_match:
                text = json_match.group(0)
            
            # Method 3: Try to find lines that look like JSON
            if not text.startswith('{'):
                # Find first line with {
                lines = text.split('\n')
                start_idx = -1
                end_idx = -1
                brace_count = 0
                
                for i, line in enumerate(lines):
                    if '{' in line and start_idx == -1:
                        start_idx = i
                    
                    if start_idx != -1:
                        brace_count += line.count('{') - line.count('}')
                        if brace_count == 0:
                            end_idx = i + 1
                            break
                
                if start_idx != -1 and end_idx != -1:
                    text = '\n'.join(lines[start_idx:end_idx])
            
            # Parse JSON
            text = self.repair_json(text)
            result = json.loads(text)

            # Validate required fields
            return {
                'has_vulnerability': result.get('has_vulnerability', False),
                'cwe_id': result.get('cwe_id'),
                'confidence': result.get('confidence', 'unknown'),
                'reasoning': result.get('reasoning', '')
            }
        except Exception as e:
            # More detailed error logging
            print(f"JSON Parse Error: {type(e).__name__}: {e}")
            print(f"First 300 chars: {response_text[:300]}")
            
            # Fallback: simple keyword detection
            has_vuln = any(word in response_text.lower() 
                          for word in ['vulnerability', 'vulnerable', 'injection', 'xss', 'insecure'])
            
            # Try to extract CWE with regex
            cwe_match = re.search(r'CWE[-\s]?(\d+)', response_text, re.IGNORECASE)
            cwe_id = f"CWE-{cwe_match.group(1)}" if cwe_match else None
            
            return {
                'has_vulnerability': has_vuln,
                'cwe_id': cwe_id,
                'confidence': 'low',
                'reasoning': 'Failed to parse structured response'
            }

    def analyze_code(self, code: str, test_name: str) -> LLMFinding:
        """
        Analyze a single test case with the LLM
        """
        start_time = time.time()
        
        try:
            prompt = self.create_prompt(code, test_name)
            
            # Prepare API call parameters
            if self.model_name == 'deepseek':
                # DeepSeek via RITS
                api_params = {
                    'model': self.model_id,
                    'messages': [{'role': 'user', 'content': prompt}],
                    'max_tokens': 500,
                    'temperature': 0,
                    'api_base': self.model_config.get('api_base', None),
                    'extra_headers': {
                        'RITS_API_KEY': os.getenv('RITS_API_KEY')
                    }
                }
            elif self.model_name.lower() in ['gpt-oss', 'granite', 'qwen']:
                # GPT via Ollama
                llm = ChatOllama(model=self.model_id, temperature=0)
                response_obj = llm.invoke(prompt)
                response_text = response_obj.content
                parsed = self.parse_llm_response(response_text)
                
                response_time = time.time() - start_time
                
                return LLMFinding(
                    test_name=test_name,
                    detected=parsed['has_vulnerability'],
                    detected_cwe=parsed['cwe_id'],
                    confidence=parsed['confidence'],
                    reasoning=parsed['reasoning'],
                    response_time=response_time
                )
            else:
                # Claude via standard APIs
                api_params = {
                    'model': self.model_id,
                    'messages': [{'role': 'user', 'content': prompt}],
                    'max_tokens': 500,
                    'temperature': 0
                }
            
            # Call LLM
            response = completion(**api_params)
            response_text = response.choices[0].message.content
            
            # Parse response
            parsed = self.parse_llm_response(response_text)
            
            response_time = time.time() - start_time
            
            return LLMFinding(
                test_name=test_name,
                detected=parsed['has_vulnerability'],
                detected_cwe=parsed['cwe_id'],
                confidence=parsed['confidence'],
                reasoning=parsed['reasoning'],
                response_time=response_time
            )
            
        except Timeout as e:
            print(f"Timeout for {test_name}")
            return LLMFinding(test_name, False, None, 'error', 'Timeout', time.time() - start_time)
        except RateLimitError as e:
            print(f"Rate limit exceeded, waiting 60s...")
            time.sleep(60)
            return self.analyze_code(code, test_name) # Retry
        except Exception as e:
            print(f"Error analyzing {test_name}")
            return LLMFinding(test_name, False, None, 'error', str(e), time.time() - start_time)

class OWASPBenchmarkTester:
    """
    Test LLMs on OWASP Benchmark
    """
    
    def __init__(self, benchmark_dir: str, expected_results_csv: str):
        """
        Initialize OWASP Benchmark tester
        """
        self.benchmark_dir = Path(benchmark_dir)
        self.expected_results = self.load_expected_results(expected_results_csv)
        self.analysis_state = False
        
    def load_expected_results(self, csv_path: str) -> pd.DataFrame:
        """Load ground truth from OWASP Benchmark"""
        df = pd.read_csv(csv_path, usecols=range(4))
        df.columns = ['test_name', 'category', 'real_vulnerability', 'cwe']
        
        # Normalize CWE format
        df['cwe'] = df['cwe'].apply(lambda x: f"CWE-{x}" if pd.notna(x) else None)
        
        df = df.sort_values('test_name').reset_index(drop=True)

        self.cwe_category_map = df.dropna(subset=['cwe']).set_index('cwe')['category'].to_dict()

        print(f"Loaded {len(df)} test cases")
        print(f"True vulnerabilities: {df['real_vulnerability'].sum()}")
        print(f"False positives: {(~df['real_vulnerability']).sum()}")
        
        return df
    
    def load_test_code(self, test_name: str) -> Optional[str]:
        """Load Java code for a test case"""
        # OWASP Benchmark structure: BenchmarkTest00001.java
        test_file = self.benchmark_dir / f"{test_name}.java"
        
        if not test_file.exists():
            print(f"Test file not found: {test_file}")
            return None
        
        with open(test_file, 'r', encoding='utf-8') as f:
            return f.read()
    
    def load_cached_results(self, model_name: str) -> Dict[str, Dict]:
        result_file = Path(f'../results/llm/{model_name}_owasp_results.json')
        if not result_file.exists():
            return {}

        with open(result_file, 'r') as f:
            data = json.load(f)

        return {r['test_name']: r for r in data.get('results', [])}

    def test_llm(self, llm_tester: LLMSASTTester, limit: Optional[int] = None) -> List[Dict]:
        """
        Test LLM on OWASP Benchmark
        """
        self.analysis_state = False
        print(f"TESTING {llm_tester.model_name.upper()} ON OWASP BENCHMARK")
        
        cached_results = self.load_cached_results(llm_tester.model_name)

        results_cache = []
        results = []
        test_cases = self.expected_results.head(limit) if limit else self.expected_results
        
        for idx, row in test_cases.iterrows():
            test_name = row['test_name']
            expected_category = row['category']
            expected_vuln = row['real_vulnerability']
            expected_cwe = row['cwe']

            print(f"Testing {idx+1}/{len(test_cases)}: {test_name}...", end=' ')
            
            if test_name in cached_results:
                cached = cached_results[test_name]
                
                # Ensure required keys exist
                if 'detected' in cached and 'detected_cwe' in cached:
                    print("Cached *")
                    results.append(cached)
                    time.sleep(0.2)
                    continue
            
            # Load code
            code = self.load_test_code(test_name)
            if not code:
                continue
            
            # Analyze with LLM
            finding = llm_tester.analyze_code(code, test_name)
            self.analysis_state = True

            if finding.confidence == 'error':
                continue
            
            # Evaluate
            true_positive = expected_vuln and finding.detected
            false_positive = not expected_vuln and finding.detected
            true_negative = not expected_vuln and not finding.detected
            false_negative = expected_vuln and not finding.detected
            
            # Check CWE accuracy
            cwe_correct = (finding.detected_cwe == expected_cwe) if finding.detected_cwe else False
            
            # Check category accuracy
            if finding.detected_cwe:
                detected_category = self.cwe_category_map.get(finding.detected_cwe)
                category_correct = (expected_category == detected_category)
            else:
                detected_category = None
                category_correct = None
            
            result = {
                'test_name': test_name,
                'expected_vuln': expected_vuln,
                'detected': finding.detected,
                'expected_category': expected_category,
                'detected_category': detected_category,
                'category_correct': category_correct,
                'expected_cwe': expected_cwe,
                'detected_cwe': finding.detected_cwe,
                'cwe_correct': cwe_correct,
                'true_positive': true_positive,
                'false_positive': false_positive,
                'true_negative': true_negative,
                'false_negative': false_negative,
                'confidence': finding.confidence,
                'reasoning': finding.reasoning,
                'response_time': finding.response_time
            }
            results.append(result)
            
            # Print result
            if true_positive:
                cwe_status = "Correct CWE" if cwe_correct else "Wrong CWE"
                print(f"Correct TP - {cwe_status} ({finding.response_time:.1f}s) - Correct CWE: {expected_cwe}, Detected CWE: {finding.detected_cwe}")
            elif false_positive:
                print(f"Wrong FP - ({finding.response_time:.1f}s) - Detected CWE: {finding.detected_cwe}")
            elif true_negative:
                print(f"Correct TN - ({finding.response_time:.1f}s)")
            else:  # false_negative
                print(f"Wrong FN - ({finding.response_time:.1f}s) - Missed vulnerability CWE: {expected_cwe}")
            
            # Save results every 100 tests
            if (idx + 1) % 100 == 0:
                print(f"\nProcessed {idx + 1} tests, saving results...")
                metrics = self.calculate_metrics(results)
                self.save_results(llm_tester.model_name, llm_tester.model_id, results, metrics)
                results_cache.extend(results)
                results = [] # reset results after saving
        
            # Rate limiting consideration
            if (idx + 1) % 50 == 0:
                print(f"\nProcessed {idx+1} tests, pausing 10s to avoid rate limits...\n")
                time.sleep(10)
            
        if results:
            print(f"\nFinal batch of {len(results)} tests, saving results...\n")
            metrics = self.calculate_metrics(results)
            self.save_results(llm_tester.model_name, llm_tester.model_id, results, metrics)
            results_cache.extend(results)
        
        return results_cache
    
    def calculate_metrics(self, results: List[Dict]) -> Dict:
        """Calculate performance metrics"""
        tp = sum(r['true_positive'] for r in results)
        fp = sum(r['false_positive'] for r in results)
        tn = sum(r['true_negative'] for r in results)
        fn = sum(r['false_negative'] for r in results)
        
        # CWE accuracy (among detections)
        detections = [r for r in results if r['detected']]
        cwe_correct = sum(r['cwe_correct'] for r in detections)
        cat_correct = sum(r['category_correct'] for r in detections if r['category_correct'] is not None)
        
        # Calculate metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / len(results) if results else 0
        
        cwe_accuracy = cwe_correct / len(detections) if detections else 0
        
        # Only count detections where category_correct is not None
        detections_with_category = [r for r in detections if r['category_correct'] is not None]
        cat_accuracy = cat_correct / len(detections_with_category) if detections_with_category else 0
    
        avg_time = sum(r['response_time'] for r in results) / len(results) if results else 0
        
        return {
            'total_tests': len(results),
            'true_positives': tp,
            'false_positives': fp,
            'true_negatives': tn,
            'false_negatives': fn,
            'precision': precision * 100,
            'recall': recall * 100,
            'f1_score': f1,
            'accuracy': accuracy * 100,
            'cwe_accuracy': cwe_accuracy * 100,
            'category_accuracy': cat_accuracy * 100,
            'detections': len(detections),
            'cwe_correct': cwe_correct,
            'category_correct': cat_correct,
            'avg_response_time': avg_time
        }
    
    def print_summary(self, results: List[Dict], metrics: Dict):
        """Print test summary"""
        print("\nSUMMARY\n")
        
        print(f"Total Tests:        {metrics['total_tests']}")
        print(f"True Positives:     {metrics['true_positives']}")
        print(f"False Positives:    {metrics['false_positives']}")
        print(f"True Negatives:     {metrics['true_negatives']}")
        print(f"False Negatives:    {metrics['false_negatives']}")
        print()
        print(f"Precision:          {metrics['precision']:.2f}%")
        print(f"Recall (TPR):       {metrics['recall']:.2f}%")
        print(f"F1 Score:           {metrics['f1_score']:.3f}")
        print(f"Accuracy:           {metrics['accuracy']:.2f}%")
        
        print()
        print(f"Avg Response Time:  {metrics['avg_response_time']:.2f}s")
    
    def save_results(self, model_name: str, model_id: str, results: List[Dict], metrics: Dict, output_dir: str = '../results/llm'):
        output_file = Path(output_dir) / f"{model_name}_owasp_results.json"

        if output_file.exists():
            with open(output_file, 'r') as f:
                existing = json.load(f)
                existing_results = {r['test_name']: r for r in existing['results']}
        else:
            existing_results = {}

        for r in results:
            existing_results[r['test_name']] = r

        sorted_results = sorted(
            existing_results.values(),
            key=lambda r: r['test_name']
        )

        output_data = {
            'model': model_name,
            'model_id': model_id,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'metrics': metrics,
            'results': sorted_results
        }

        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)

        if self.analysis_state:
            print(f"Results saved to: {output_file}")
        else:
            print(f"Results not updated. Results saved: {output_file}")

def main():
    """
    Main function to test multiple LLMs on OWASP Benchmark
    """
    # Configuration
    BENCHMARK_DIR = '/Users/ibrahimmalik/Documents/code_tests/code-analysis/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode'
    EXPECTED_CSV = '/Users/ibrahimmalik/Documents/code_tests/code-analysis/BenchmarkJava/expectedresults-1.2.csv'
    
    # Initialize benchmark tester
    benchmark = OWASPBenchmarkTester(BENCHMARK_DIR, EXPECTED_CSV)
    
    # Define models to test
    models = [
        # ('gpt4o', {}),
        # ('gpt-oss', {}),
        # ('claude', {}),
        # ('deepseek', {
        #     'api_base': 'https://inference-3scale-apicast-production.apps.rits.fmaas.res.ibm.com/deepseek-coder-33b-instruct/v1'
        # }),
        ('granite', {}),
        ('qwen', {})
    ]
    
    # Test each model
    all_results = {}
    
    for model_name, config in models:
        try:
            print(f"\n##### TESTING: {model_name.upper()} #####\n")
            
            # Initialize LLM tester
            llm_tester = LLMSASTTester(model_name, config)
            
            # limit=10 for quick testing, remove for full run
            results = benchmark.test_llm(llm_tester, limit=500)
            
            # Calculate metrics
            metrics = benchmark.calculate_metrics(results)
            
            if not metrics['total_tests']:
                print(f"\nNo tests were run for {model_name}. Skipping summary.")
                continue

            # Print summary
            benchmark.print_summary(results, metrics)

            # Store for comparison
            all_results[model_name] = metrics
            
        except Exception as e:
            print(f"\nError testing {model_name}: {e}")
            continue
    
    # Final comparison
    if len(all_results) > 1:
        print("\n##### COMPARISON ACROSS MODELS #####\n")
        
        print(f"{'Model':<15} {'Precision':<12} {'Recall':<12} {'F1':<10} {'CWE Acc':<12}")
        for model, metrics in all_results.items():
            print(f"{model:<15} {metrics['precision']:>6.2f}%     {metrics['recall']:>6.2f}%     "
                  f"{metrics['f1_score']:>6.3f}   {metrics['cwe_accuracy']:>6.2f}%")

if __name__ == "__main__":
    main()
