"""
Main Analysis Process
Integrates all analysis modules to implement complete shake-to-ad detection workflow
"""
import os
import json
import time
from typing import List, Dict, Any, Optional
from pathlib import Path
import networkx as nx

from src.utils.logger import log
from src.utils.apk_reverser import ApkReverser
from src.detector.sensor_logic_detector import SensorLogicDetector
from src.detector.obfuscation_resistant_detector import ObfuscationResistantDetector
from src.analyzer.threshold_extractor import ThresholdExtractor, extract_thresholds_from_code
from src.analyzer.parameter_tracker import ParameterOriginTracker, track_parameters_from_code
from src.analyzer.external_parameter_detector import ExternalParameterDetector
from src.analyzer.llm_analyzer import LLMAnalyzer
from src.analyzer.result_filter import ResultFilter
from src.utils.string_decoder import StringReplacer, StringAnalyzer


class SSARAnalyzer:
    """Shake-to-ad detection analyzer"""
    
    def __init__(self, apk_name: str):
        self.apk_name = apk_name
        self.current_dir = Path(__file__).parent.parent.resolve()
        self.apk_dir = self.current_dir / "apk" / apk_name
        self.info_dir = self.current_dir / "info"
        self.filtered_dir = self.current_dir / "filtered_results"
        
        # Ensure directories exist
        self.info_dir.mkdir(exist_ok=True)
        self.filtered_dir.mkdir(exist_ok=True)
        
        # Initialize analysis modules
        self.sensor_detector = SensorLogicDetector()
        self.obfuscation_detector = ObfuscationResistantDetector()
        self.threshold_extractor = ThresholdExtractor()
        self.param_tracker = ParameterOriginTracker()
        self.external_param_detector = ExternalParameterDetector()
        self.llm_analyzer = LLMAnalyzer()
        self.result_filter = ResultFilter()
        self.string_replacer = StringReplacer()
        self.string_analyzer = StringAnalyzer()
        
        log.info(f"Initializing SSAR analyzer, target APK: {apk_name}")
        log.debug(f"Project root: {self.current_dir}")
        log.debug(f"APK directory path: {self.apk_dir}")
        log.debug(f"APK directory exists: {self.apk_dir.exists()}")
    
    def run_full_analysis(self) -> Dict[str, Any]:
        """Run complete analysis workflow"""
        
        start_time = time.time()
        log.info("Starting complete SSAR analysis workflow")
        
        try:
            # Step 1: Sensor logic detection
            sensor_results = self._detect_sensor_logic()
            if not sensor_results:
                log.warning("No sensor logic found, analysis ended")
                return self._create_empty_result()
            
            # Step 2: Detailed analysis of each candidate file
            analysis_results = self._analyze_sensor_files(sensor_results)
            
            # Step 3: Save raw analysis results
            self._save_raw_results(analysis_results)
            
            # Step 4: Filter and process results
            filtered_results = self._filter_and_process_results(analysis_results)
            
            # Step 5: Save final results
            final_report = self._save_final_results(filtered_results)
            
            end_time = time.time()
            duration = end_time - start_time
            
            log.success(f"SSAR analysis completed, time taken: {duration:.2f}s")
            return final_report
            
        except Exception as e:
            log.error(f"SSAR analysis failed: {e}")
            return self._create_error_result(str(e))
    
    def _detect_sensor_logic(self) -> List[Dict[str, Any]]:
        """Detect sensor logic with anti-obfuscation capabilities"""
        
        log.info("Step 1: Detecting sensor logic with anti-obfuscation")
        
        if not self.apk_dir.exists():
            log.error(f"APK directory does not exist: {self.apk_dir}")
            return []
        
        # Use traditional sensor logic detector
        traditional_results = self.sensor_detector.analyze_directory(str(self.apk_dir))
        
        # Use obfuscation-resistant detector for additional coverage
        robust_results = self._detect_sensor_logic_robust()
        
        # Combine results, prioritizing robust detection for obfuscated code
        combined_results = self._combine_detection_results(traditional_results, robust_results)
        
        log.info(f"Enhanced sensor logic detection completed, found {len(combined_results)} candidate files")
        return combined_results
    
    def _detect_sensor_logic_robust(self) -> List[Dict[str, Any]]:
        """Detect sensor logic using anti-obfuscation techniques"""
        robust_results = []
        processed_count = 0
        start_time = time.time()
        
        # Count total Java files first
        total_files = 0
        for root, _, files in os.walk(str(self.apk_dir)):
            for file in files:
                if file.endswith(".java"):
                    total_files += 1
        
        log.info(f"Starting robust sensor logic detection for {total_files} Java files")
        
        for root, _, files in os.walk(str(self.apk_dir)):
            for file in files:
                if not file.endswith(".java"):
                    continue
                
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Skip empty files
                    if not content.strip():
                        continue
                    
                    # Pre-process content to handle obfuscated strings
                    processed_content = self.string_replacer.replace_obfuscated_strings(content)
                    
                    # Use robust detector
                    result = self.obfuscation_detector.detect_sensor_logic_robust(file_path, processed_content)
                    
                    if result['is_likely_sensor_logic']:
                        robust_results.append(result)
                    
                    processed_count += 1
                    
                    # Log progress every 100 files
                    if processed_count % 1000 == 0:
                        elapsed_time = time.time() - start_time
                        log.info(f"Processed {processed_count}/{total_files} files ({processed_count/total_files*100:.1f}%), elapsed: {elapsed_time:.2f}s")
                        
                except Exception as e:
                    log.warning(f"Failed to analyze file {file_path}: {e}")
                    continue
        
        total_time = time.time() - start_time
        log.info(f"Robust detection completed: {processed_count} files processed in {total_time:.2f}s, found {len(robust_results)} candidates")
        
        return robust_results
    
    def _combine_detection_results(self, traditional_results: List[Dict], robust_results: List[Dict]) -> List[Dict]:
        """Combine results from traditional and robust detection methods"""
        combined = []
        
        # Add traditional results
        for result in traditional_results:
            result['detection_method'] = 'traditional'
            combined.append(result)
        
        # Add robust results that weren't found by traditional method
        traditional_files = {result.get('file_path', '') for result in traditional_results}
        
        for result in robust_results:
            if result.get('file_path', '') not in traditional_files:
                result['detection_method'] = 'robust'
                combined.append(result)
        
        return combined
    
    def _analyze_sensor_files(self, sensor_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze sensor files with enhanced field-level tracking"""
        
        log.info("Step 2: Detailed analysis of sensor files")
        
        analysis_tasks = []
        
        for idx, sensor_result in enumerate(sensor_results, 1):
            file_path = sensor_result.get("file_path", "")
            
            # Handle different result formats from traditional vs robust detection
            if "content" in sensor_result:
                content = sensor_result["content"]
            else:
                # For robust detection results, we need to read the file content
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                except Exception as e:
                    log.warning(f"Failed to read file {file_path}: {e}")
                    continue
            
            # Skip if file_path is empty or content is empty
            if not file_path or not content:
                log.warning(f"Skipping file with empty path or content: {file_path}")
                continue
            
            log.info(f"Analyzing file {idx}/{len(sensor_results)}: {os.path.basename(file_path)}")
            
            # Threshold extraction
            thresholds = extract_thresholds_from_code(content)
            threshold_dict = {t.variable_name: t.value for t in thresholds}
            
            # Enhanced parameter tracking with field-level analysis
            param_graph = track_parameters_from_code(content)
            param_origins = {}
            
            # Extract parameter origin information from graph
            for node in param_graph.nodes():
                node_data = param_graph.nodes[node]
                param_origins[node] = {
                    "level": node_data.get("level", "unknown"),
                    "value": node_data.get("value", None),
                    "type": node_data.get("type", None),
                    "field_type": node_data.get("field_type", None),
                    "sensor_type": node_data.get("sensor_type", None)
                }
            
            # Enhanced: Extract field-level tracking information
            field_tracking_info = self._extract_field_tracking_info(content)
            
            # Enhanced: Extract shake-to-ad specific method fragments
            shake_methods = self._extract_shake_method_fragments(content)
            
            # Enhanced: Extract threshold propagation information
            threshold_propagation = self._extract_threshold_propagation(content, threshold_dict)
            
            # Build analysis task
            task = {
                "index": idx,
                "file_path": file_path,
                "code_snippet": content,
                "thresholds": threshold_dict,
                "external_params": self._extract_external_params(content),
                "dynamic_sources": self._extract_dynamic_sources(sensor_result),
                "call_graph": self._build_call_graph(content),
                "param_origin": param_origins,
                # Enhanced: Add field-level tracking information
                "field_tracking": field_tracking_info,
                "shake_methods": shake_methods,
                "threshold_propagation": threshold_propagation
            }
            
            analysis_tasks.append(task)
        
        # Batch LLM analysis
        log.info("Starting batch LLM analysis")
        llm_results = self.llm_analyzer.batch_analyze(analysis_tasks)
        
        # Integrate results
        final_results = []
        for task, llm_result in zip(analysis_tasks, llm_results):
            result = {
                "index": task["index"],
                "file": task["file_path"],
                "analysis": llm_result
            }
            final_results.append(result)
        
        return final_results
    
    def _extract_field_tracking_info(self, content: str) -> Dict[str, Any]:
        """Extract comprehensive field-level tracking information"""
        try:
            import javalang
            tree = javalang.parse.parse(content)
            
            # Use field tracker to get detailed information
            from src.analyzer.field_tracker import SensorFieldTracker
            field_tracker = SensorFieldTracker()
            field_graph = field_tracker.track_sensor_field_flow(tree)
            
            # Get comprehensive field tracking summary
            field_summary = field_tracker.get_sensor_field_summary()
            
            return {
                "sensor_fields": field_tracker.sensor_fields,
                "field_accesses": field_tracker.field_accesses,
                "cross_method_flows": field_tracker.cross_method_flows,
                "field_summary": field_summary,
                "field_graph_nodes": len(field_graph.nodes),
                "field_graph_edges": len(field_graph.edges)
            }
        except Exception as e:
            log.warning(f"Field tracking extraction failed: {e}")
            return {}
    
    def _extract_shake_method_fragments(self, content: str) -> List[Dict[str, Any]]:
        """Extract shake-to-ad specific method fragments"""
        shake_methods = []
        
        try:
            import javalang
            tree = javalang.parse.parse(content)
            
            # Look for shake-related method patterns
            shake_patterns = [
                "onShake", "handleShake", "processShake", "shakeDetected",
                "onSensorChanged", "onAccelerometerChanged", "onMotionDetected",
                "triggerAd", "showAd", "loadAd", "displayAd"
            ]
            
            for path, method in tree.filter(javalang.tree.MethodDeclaration):
                method_name = method.name.lower()
                
                # Check if method is shake-related
                is_shake_method = any(pattern.lower() in method_name for pattern in shake_patterns)
                
                if is_shake_method:
                    # Extract method content
                    method_content = ""
                    for child in method.children:
                        if hasattr(child, 'position'):
                            method_content += str(child)
                    
                    shake_methods.append({
                        "method_name": method.name,
                        "method_content": method_content,
                        "line_start": method.position.line if method.position else 0,
                        "is_shake_handler": "shake" in method_name.lower(),
                        "is_ad_trigger": any(ad_pattern in method_name.lower() for ad_pattern in ["ad", "trigger", "show", "load", "display"])
                    })
            
        except Exception as e:
            log.warning(f"Shake method extraction failed: {e}")
        
        return shake_methods
    
    def _extract_threshold_propagation(self, content: str, thresholds: Dict[str, float]) -> Dict[str, Any]:
        """Extract threshold propagation information"""
        threshold_propagation = {
            "thresholds_found": list(thresholds.keys()),
            "threshold_values": thresholds,
            "threshold_usage": {},
            "threshold_conditions": []
        }
        
        try:
            import javalang
            tree = javalang.parse.parse(content)
            
            # Find threshold usage in conditions
            for path, node in tree.filter(javalang.tree.IfStatement):
                condition_str = str(node.condition)
                
                # Check if condition contains any threshold
                for threshold_name in thresholds.keys():
                    if threshold_name in condition_str:
                        threshold_propagation["threshold_conditions"].append({
                            "threshold": threshold_name,
                            "condition": condition_str,
                            "line": node.position.line if node.position else 0
                        })
            
            # Find threshold assignments
            for path, node in tree.filter(javalang.tree.Assignment):
                target_str = str(node.expressionl)
                value_str = str(node.value)
                
                for threshold_name in thresholds.keys():
                    if threshold_name in target_str or threshold_name in value_str:
                        threshold_propagation["threshold_usage"][threshold_name] = {
                            "assignment": f"{target_str} = {value_str}",
                            "line": node.position.line if node.position else 0
                        }
            
        except Exception as e:
            log.warning(f"Threshold propagation extraction failed: {e}")
        
        return threshold_propagation
    
    # def _extract_external_params(self, content: str) -> Dict[str, Any]:
    #     """Extract external parameter information using comprehensive detection"""
        
    #     try:
    #         import javalang
    #         tree = javalang.parse.parse(content)
            
    #         # Use the new external parameter detector
    #         external_analysis = self.external_param_detector.analyze_external_parameters(tree)
            
    #         # Categorize the results
    #         categorization = self.external_param_detector.categorize_parameters(external_analysis)
            
    #         # Return comprehensive external parameter information
    #         return {
    #             "analysis_results": external_analysis,
    #             "categorization": categorization,
    #             "summary": categorization["summary"]
    #         }
            
    #     except Exception as e:
    #         log.warning(f"Failed to extract external parameters: {e}")
    #         # Fallback to simple regex-based extraction
    #         return self._extract_external_params_fallback(content)
    
    def _extract_external_params(self, content: str) -> Dict[str, str]:
        """Fallback method for external parameter extraction"""
        
        import re
        external_params = {}
        
        # Field declaration
        field_pattern = re.compile(r'private\s+(?:static\s+)?(?:final\s+)?(\w+)\s+(\w+)\s*=\s*(.+?);')
        for match in field_pattern.finditer(content):
            param_type, param_name, value = match.groups()
            external_params[param_name] = value.strip()
        
        # Method parameters
        method_pattern = re.compile(r'(?:public|private|protected)\s+\w+\s+\w+\(([^)]*)\)')
        for match in method_pattern.finditer(content):
            params_str = match.group(1)
            if params_str.strip():
                for param in params_str.split(','):
                    param = param.strip()
                    if param:
                        parts = param.split()
                        if len(parts) >= 2:
                            param_name = parts[-1]
                            external_params[param_name] = "method_parameter"
        
        return external_params
    
    def _extract_dynamic_sources(self, sensor_result: Dict[str, Any]) -> List[str]:
        """Extract dynamic data sources"""
        
        features = sensor_result.get("features", {})
        dynamic_sources = []
        
        # Extract from AST features
        if "registration_calls" in features:
            for call in features["registration_calls"]:
                if call.get("method"):
                    dynamic_sources.append(call["method"])
        
        return dynamic_sources
    
    def _build_call_graph(self, content: str) -> nx.DiGraph:
        """Build call relationship graph"""
        
        import javalang
        graph = nx.DiGraph()
        
        try:
            tree = javalang.parse.parse(content)
            
            for path, node in tree.filter(javalang.tree.MethodInvocation):
                if hasattr(node, 'qualifier') and hasattr(node, 'member'):
                    if node.qualifier:
                        graph.add_edge(str(node.qualifier), node.member)
                    else:
                        graph.add_node(node.member)
                        
        except Exception as e:
            log.warning(f"Build call graph failed: {e}")
        
        return graph
    
    def _save_raw_results(self, results: List[Dict[str, Any]]) -> None:
        """Save raw analysis results"""
        
        output_file = self.info_dir / f"{self.apk_name}_results.json"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        log.info(f"Raw analysis results saved: {output_file}")
    
    def _filter_and_process_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter and process results"""
        
        log.info("Step 4: Filter and process results")
        
        # Filter valid results
        filtered_results = self.result_filter.filter_valid_results(results)
        
        # Flatten results
        flattened_results = self.result_filter.flatten_results(filtered_results)
        
        return flattened_results
    
    def _save_final_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Save final results and generate report"""
        
        log.info("Step 5: Save final results")
        
        # Save filtered results
        output_file = self.filtered_dir / f"{self.apk_name}_filtered_results.json"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        log.info(f"Filtered results saved: {output_file}")
        
        # Generate summary report
        summary_report = self.result_filter.generate_summary_report(results)
        summary_report.update({
            "apk_name": self.apk_name,
            "analysis_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "output_files": {
                "raw_results": str(self.info_dir / f"{self.apk_name}_results.json"),
                "filtered_results": str(output_file)
            }
        })
        
        # Save summary report
        summary_file = self.filtered_dir / f"{self.apk_name}_summary.json"
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary_report, f, ensure_ascii=False, indent=2)
        
        log.success(f"Analysis summary saved: {summary_file}")
        
        return summary_report
    
    def _create_empty_result(self) -> Dict[str, Any]:
        """Create empty result"""
        return {
            "apk_name": self.apk_name,
            "analysis_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_count": 0,
            "valid_count": 0,
            "summary": "No sensor-related logic found"
        }
    
    def _create_error_result(self, error_msg: str) -> Dict[str, Any]:
        """Create error result"""
        return {
            "apk_name": self.apk_name,
            "analysis_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "error": error_msg,
            "summary": "Error occurred during analysis"
        }


def analyze_apk(apk_name: str) -> Dict[str, Any]:
    """
    Analyze the shake-to-ad mode of the specified APK
    
    Args:
        apk_name: APK file name
        
    Returns:
        Dict[str, Any]: Analysis result report
    """
    analyzer = SSARAnalyzer(apk_name)
    return analyzer.run_full_analysis()



